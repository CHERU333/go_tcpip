package network

import (
	"context" // リクエストの伝播、タイムアウトの設定、キャンセル通知
	"fmt"     // 文字列の生成や出力、スキャン
	"log"     // ログの出力
	"os"      // ファイルの操作やプロセスの実行、環境変数の取得
	"syscall" // ファイル操作やプロセス管理、ネットワーク操作
	"unsafe"  // 低レベルなメモリ操作を行う
)

type ifreq struct {
	ifrName  [16]byte
	ifrFlags int16
}

const (
	TUNSETIFF   = 0x400454ca
	IFF_TUN     = 0x0001
	IFF_NO_PI   = 0x1000
	PACKET_SIZE = 2048
	QUEUE_SIZE  = 10
)

type Packet struct {
	Buf []byte
	N   uintptr
}

type NetDevice struct {
	file          *os.File
	incomingQueue chan Packet
	outgoingQueue chan Packet
	ctx           context.Context
	cancel        context.CancelFunc
}

func NewTun() (*NetDevice, error) {
	// os.OpenFileはnameに/dev/net/tunを指定して、TUNデバイスを開く
	// flagにos.O_RDWRを指定して、読み書き権限許可、permに0を指定しファイルの新規作成を許可
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open error: %s", err.Error())
	}
	// ifreq：ネットワークインターフェースの設定を行うための構造体
	ifr := ifreq{}
	copy(ifr.ifrName[:], []byte("tun0"))
	// IFF_TUN：TUNデバイスを作成するフラグ, IFF_NO_PI：パケット情報を含まないフラグ
	ifr.ifrFlags = IFF_TUN | IFF_NO_PI
	// syscall.SYS_IOCTLでTUNSETIFFシステムコールを呼び出し、TUNデバイスを作成
	_, _, sysErr := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(TUNSETIFF), uintptr(unsafe.Pointer(&ifr)))
	if sysErr != 0 {
		return nil, fmt.Errorf("ioctl error: %s", sysErr.Error())
	}

	return &NetDevice{
		file:          file,
		incomingQueue: make(chan Packet, QUEUE_SIZE),
		outgoingQueue: make(chan Packet, QUEUE_SIZE),
	}, nil
}

func (t *NetDevice) Close() error {
	err := t.file.Close()
	if err != nil {
		return fmt.Errorf("close error: %s", err.Error())
	}
	t.cancel()

	return nil
}

// パケットの送受信
func (t *NetDevice) read(buf []byte) (uintptr, error) {
	n, _, sysErr := syscall.Syscall(syscall.SYS_READ, t.file.Fd(), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if sysErr != 0 {
		return 0, fmt.Errorf("read error: %s", sysErr.Error())
	}
	return n, nil
}

func (t *NetDevice) write(buf []byte) (uintptr, error) {
	n, _, sysErr := syscall.Syscall(syscall.SYS_WRITE, t.file.Fd(), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if sysErr != 0 {
		return 0, fmt.Errorf("write error: %s", sysErr.Error())
	}
	return n, nil
}

// パケットのキュースタック
func (tun *NetDevice) Bind() {
	// context.WithCancel を使って新しいコンテキストを作成し、
	// そのコンテキストとキャンセル関数をフィールドに割り当てる
	tun.ctx, tun.cancel = context.WithCancel(context.Background())
	// 別のゴルーチンでパケットの読み込みループを開始
	go func() {
		for {
			select {
			case <-tun.ctx.Done():
				return
			default:
				buf := make([]byte, PACKET_SIZE)
				n, err := tun.read(buf)
				if err != nil {
					log.Printf("read error: %s", err.Error())
				}
				packet := Packet{
					Buf: buf[:n],
					N:   n,
				}
				tun.incomingQueue <- packet
			}
		}
	}()

	go func() {
		for {
			select {
			case <-tun.ctx.Done():
				return

			case pkt := <-tun.outgoingQueue:
				_, err := tun.write(pkt.Buf[:pkt.N])
				if err != nil {
					log.Printf("write error: %s", err.Error())
				}
			}
		}
	}()
}

// パケットを読み込む
func (t *NetDevice) Read() (Packet, error) {
	pkt, ok := <-t.incomingQueue
	if !ok {
		return Packet{}, fmt.Errorf("incoming queue is closed")
	}
	return pkt, nil
}

// パケットを書き込む
func (t *NetDevice) Write(pkt Packet) error {
	select {
	case t.outgoingQueue <- pkt:
		return nil
	case <-t.ctx.Done():
		return fmt.Errorf("device closed")
	}
}
