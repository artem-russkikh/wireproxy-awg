package wireproxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// DNSCache кэширует DNS запросы
type DNSCache struct {
	cache map[string]*cacheEntry
	mu    sync.RWMutex
	ttl   time.Duration
}

type cacheEntry struct {
	ip        net.IP
	timestamp time.Time
}

// NewDNSCache создает новый DNS кэш
func NewDNSCache(ttl time.Duration) *DNSCache {
	return &DNSCache{
		cache: make(map[string]*cacheEntry),
		ttl:   ttl,
	}
}

// Resolve разрешает домен с кэшированием
func (d *DNSCache) Resolve(host string) (net.IP, error) {
	// Проверяем кэш
	d.mu.RLock()
	if entry, exists := d.cache[host]; exists {
		if time.Since(entry.timestamp) < d.ttl {
			d.mu.RUnlock()
			return entry.ip, nil
		}
	}
	d.mu.RUnlock()

	// Не найдено в кэше или устарело - делаем запрос
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed for %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP found for %s", host)
	}

	// Берем первый IPv4 адрес
	var ip net.IP
	for _, candidate := range ips {
		if candidate.To4() != nil {
			ip = candidate
			break
		}
	}
	if ip == nil {
		ip = ips[0] // Берем IPv6 если нет IPv4
	}

	// Сохраняем в кэш
	d.mu.Lock()
	d.cache[host] = &cacheEntry{
		ip:        ip,
		timestamp: time.Now(),
	}
	d.mu.Unlock()
	return ip, nil
}

// UDPConnection представляет UDP соединение
type UDPConnection struct {
	conn        net.Conn
	lastUsed    time.Time
	client      *net.UDPAddr
	targetAddr  *net.UDPAddr
	resolvedIP  net.IP
	readerDone  chan bool
	writeMutex  sync.Mutex // ⚡️ Мьютекс для записи
}

// UDPConnectionPool управляет пулом UDP соединений
type UDPConnectionPool struct {
	connections   map[string]*UDPConnection
	mu            sync.RWMutex
	dnsCache      *DNSCache
	maxSize       int
	currentSize   int
	mtu           int
	creationLock  sync.Map // Защита от дублирования при создании соединений
}

// Пул буферов для уменьшения аллокаций
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 1500) // ⚡️ Оптимально для игр
	},
}

// Пул буферов для UDP reader'ов
var readerBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 1500) // Достаточно для MTU
	},
}

// NewUDPConnectionPool создает новый UDP connection pool
func NewUDPConnectionPool(maxSize int, mtu int) *UDPConnectionPool {
	return &UDPConnectionPool{
		connections: make(map[string]*UDPConnection),
		dnsCache:    NewDNSCache(5 * time.Second), // ⚡️ 5 секунд кэш DNS
		maxSize:     maxSize,
		currentSize: 0,
		mtu:         mtu,
	}
}

// Get возвращает соединение из пула
func (p *UDPConnectionPool) Get(key string) (*UDPConnection, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	conn, exists := p.connections[key]
	if exists {
		conn.lastUsed = time.Now()
	}
	return conn, exists
}

// Set добавляет соединение в пул
func (p *UDPConnectionPool) Set(key string, conn *UDPConnection) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.currentSize >= p.maxSize {
		p.cleanupOldestLocked(5)
	}
	conn.lastUsed = time.Now()
	p.connections[key] = conn
	p.currentSize++
}

// Delete удаляет соединение из пула
func (p *UDPConnectionPool) Delete(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if conn, exists := p.connections[key]; exists {
		select {
		case conn.readerDone <- true:
		default:
		}
		conn.conn.Close()
		delete(p.connections, key)
		p.currentSize--
	}
	// Убираем флаг создания
	p.creationLock.Delete(key)
}

// Cleanup удаляет старые соединения
func (p *UDPConnectionPool) Cleanup(maxAge time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cleanupOldLocked(maxAge)
}

// cleanupOldLocked удаляет старые соединения
func (p *UDPConnectionPool) cleanupOldLocked(maxAge time.Duration) {
	now := time.Now()
	toDelete := make([]string, 0, 10)
	for key, conn := range p.connections {
		if now.Sub(conn.lastUsed) > maxAge {
			toDelete = append(toDelete, key)
		}
	}
	for _, key := range toDelete {
		if conn, exists := p.connections[key]; exists {
			select {
			case conn.readerDone <- true:
			default:
			}
			conn.conn.Close()
			delete(p.connections, key)
			p.currentSize--
		}
		p.creationLock.Delete(key)
	}
}

// cleanupOldestLocked удаляет самые старые соединения
func (p *UDPConnectionPool) cleanupOldestLocked(count int) {
	if p.currentSize <= count {
		return
	}
	oldest := make([]string, 0, count)
	for key, conn := range p.connections {
		if len(oldest) < count {
			oldest = append(oldest, key)
			continue
		}
		for i, oldKey := range oldest {
			if conn.lastUsed.Before(p.connections[oldKey].lastUsed) {
				oldest[i] = key
				break
			}
		}
	}
	for _, key := range oldest {
		if conn, exists := p.connections[key]; exists {
			select {
			case conn.readerDone <- true:
			default:
			}
			conn.conn.Close()
			delete(p.connections, key)
			p.currentSize--
		}
		p.creationLock.Delete(key)
	}
}

// resolveTarget разрешает адрес с кэшированием
func (p *UDPConnectionPool) resolveTarget(host string, port uint16) (string, net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return net.JoinHostPort(host, strconv.Itoa(int(port))), ip, nil
	}
	ip, err := p.dnsCache.Resolve(host)
	if err != nil {
		return "", nil, err
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), ip, nil
}

// StartSocks5UDPServer запускает UDP сервер для SOCKS5
func StartSocks5UDPServer(bindAddress string, vt *VirtualTun) error {
	udpAddr, err := net.ResolveUDPAddr("udp", bindAddress)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}
	defer conn.Close()

	// Создаем пул соединений с MTU из конфига
	pool := NewUDPConnectionPool(1000, vt.Conf.MTU)

	// Запускаем очистку старых соединений
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			pool.Cleanup(60 * time.Second)
		}
	}()

	for {
		buf := bufferPool.Get().([]byte)
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			bufferPool.Put(buf)
			continue
		}
		// ⚡️ СИНХРОННАЯ обработка без горутин для уменьшения задержки
		handleSocks5UDPPacketSync(conn, clientAddr, buf[:n], vt, pool)
		bufferPool.Put(buf)
	}
}

// parseSocks5HeaderFast быстрый парсинг SOCKS5 заголовков
func parseSocks5HeaderFast(data []byte) (host string, port uint16, headerLen int, ok bool) {
	if len(data) < 10 || data[0] != 0x00 || data[1] != 0x00 || data[2] != 0x00 {
		return "", 0, 0, false
	}
	switch data[3] {
	case 0x01: // IPv4
		if len(data) < 10 {
			return "", 0, 0, false
		}
		host = net.IPv4(data[4], data[5], data[6], data[7]).String()
		port = binary.BigEndian.Uint16(data[8:10])
		headerLen = 10
		ok = true
	case 0x03: // Domain name
		domainLen := int(data[4])
		if len(data) < 7+domainLen {
			return "", 0, 0, false
		}
		host = string(data[5 : 5+domainLen])
		port = binary.BigEndian.Uint16(data[5+domainLen : 5+domainLen+2])
		headerLen = 7 + domainLen
		ok = true
	case 0x04: // IPv6
		if len(data) < 22 {
			return "", 0, 0, false
		}
		host = net.IP(data[4:20]).String()
		port = binary.BigEndian.Uint16(data[20:22])
		headerLen = 22
		ok = true
	default:
		return "", 0, 0, false
	}
	return
}

// handleSocks5UDPPacketSync обрабатывает SOCKS5 UDP пакет СИНХРОННО
func handleSocks5UDPPacketSync(serverConn *net.UDPConn, clientAddr *net.UDPAddr, data []byte, vt *VirtualTun, pool *UDPConnectionPool) {
	host, port, headerLen, ok := parseSocks5HeaderFast(data)
	if !ok {
		return
	}
	payload := data[headerLen:]

	// ⚡️ Ключ: один клиент -> одно соединение (не на пакет)
	connKey := clientAddr.String()

	// Сначала проверим, есть ли уже соединение
	if udpConn, exists := pool.Get(connKey); exists {
		// ⚡️ БЫСТРАЯ ОБРАБОТКА: синхронная отправка
		processUDPRequestSync(udpConn, payload)
		return
	}

	// Пытаемся установить флаг "в процессе создания"
	if _, loaded := pool.creationLock.LoadOrStore(connKey, struct{}{}); loaded {
		// Другая горутина уже создаёт соединение — игнорируем пакет
		return
	}

	// Создаем новое соединение асинхронно
	go func() {
		defer pool.creationLock.Delete(connKey)
		createUDPConnectionAsync(serverConn, clientAddr, host, port, payload, vt, pool, connKey)
	}()
}

// startUDPReader запускает горутину для чтения ответов
func startUDPReader(udpConn *UDPConnection, serverConn *net.UDPConn, pool *UDPConnectionPool, connKey string) {
	buf := readerBufferPool.Get().([]byte)
	defer readerBufferPool.Put(buf)

	for {
		select {
		case <-udpConn.readerDone:
			return
		default:
			udpConn.conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			n, err := udpConn.conn.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				pool.Delete(connKey)
				return
			}
			udpConn.lastUsed = time.Now()
			sendUDPResponseFast(serverConn, udpConn.client, udpConn.resolvedIP, udpConn.targetAddr.Port, buf[:n])
		}
	}
}

// processUDPRequestSync обрабатывает UDP запрос СИНХРОННО
func processUDPRequestSync(udpConn *UDPConnection, payload []byte) {
	// ⚡️ Мьютекс для предотвращения конкуренции при записи
	udpConn.writeMutex.Lock()
	defer udpConn.writeMutex.Unlock()
	udpConn.conn.Write(payload)
}

// createUDPConnectionAsync создает новое UDP соединение АСИНХРОННО
func createUDPConnectionAsync(serverConn *net.UDPConn, clientAddr *net.UDPAddr, targetHost string, targetPort uint16, payload []byte, vt *VirtualTun, pool *UDPConnectionPool, connKey string) {
	targetAddr, resolvedIP, err := pool.resolveTarget(targetHost, targetPort)
	if err != nil {
		return
	}
	host, portStr, _ := net.SplitHostPort(targetAddr)
	port, _ := strconv.Atoi(portStr)
	targetUDPAddr := &net.UDPAddr{
		IP:   net.ParseIP(host),
		Port: port,
	}
	udpConn, err := vt.Tnet.Dial("udp", targetAddr)
	if err != nil {
		return
	}
	conn := &UDPConnection{
		conn:       udpConn,
		lastUsed:   time.Now(),
		client:     clientAddr,
		targetAddr: targetUDPAddr,
		resolvedIP: resolvedIP,
		readerDone: make(chan bool, 1),
	}
	pool.Set(connKey, conn)
	// Запускаем горутину для чтения ответов
	go startUDPReader(conn, serverConn, pool, connKey)
	// Отправляем начальные данные
	processUDPRequestSync(conn, payload)
}

// sendUDPResponseFast отправляет UDP ответ клиенту SOCKS5
func sendUDPResponseFast(serverConn *net.UDPConn, clientAddr *net.UDPAddr, targetIP net.IP, targetPort int, data []byte) {
	var headerLen int
	if targetIP.To4() != nil {
		headerLen = 10
	} else {
		headerLen = 22
	}

	// Берём буфер из пула
	buf := bufferPool.Get().([]byte)
	if len(buf) < headerLen+len(data) {
		// Не хватает места — временный буфер (не возвращаем в пул)
		bufferPool.Put(buf)
		buf = make([]byte, headerLen+len(data))
	} else {
		buf = buf[:headerLen+len(data)]
	}

	// Формируем заголовок
	buf[0] = 0x00
	buf[1] = 0x00
	buf[2] = 0x00
	if targetIP.To4() != nil {
		buf[3] = 0x01
		copy(buf[4:8], targetIP.To4())
		binary.BigEndian.PutUint16(buf[8:10], uint16(targetPort))
		copy(buf[10:], data)
	} else {
		buf[3] = 0x04
		copy(buf[4:20], targetIP)
		binary.BigEndian.PutUint16(buf[20:22], uint16(targetPort))
		copy(buf[22:], data)
	}

	// Отправляем и игнорируем ошибку (UDP — best-effort)
	_, _ = serverConn.WriteToUDP(buf, clientAddr)

	// Возвращаем буфер обратно в пул, только если он из пула
	if cap(buf) == 1500 {
		bufferPool.Put(buf[:1500])
	}
}
