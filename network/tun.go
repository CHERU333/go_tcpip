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

// TUNデバイスの作成
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
	_, _, sysErr := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(syscall.TUNSETIFF), uintptr(unsafe.Pointer(&ifr)))
	if sysErr != 0 {
		return nil, fmt.Errorf("ioctl error: %s", sysErr.Error())
	}

	return &NetDevice{
		file:          file,
		incomingQueue: make(chan Packet, QUEUE_SIZE),
		outgoingQueue: make(chan Packet, QUEUE_SIZE),
	}, nil
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
			// コンテキストがキャンセルされた場合、ループを終了
			case <-tun.ctx.Done():
				return

			// デフォルトの場合
			default:
				// バッファを確保
				buf := make([]byte, PACKET_SIZE)

				// パケットを読み込む
				n, err := tun.read(buf)
				if err != nil {
					log.Printf("read error: %s", err.Error())
				}

				// 読み込んだパケットをキューに送信
				packet := Packet{
					Buf: buf[:n],
					N:   n,
				}
				tun.incomingQueue <- packet
			}
		}
	}()

	// 別のゴルーチンでパケットの書き込みループを開始
	go func() {
		for {
			select {
			// コンテキストがキャンセルされた場合、ループを終了
			case <-tun.ctx.Done():
				return

			// キューからパケットを受信した場合
			case pkt := <-tun.outgoingQueue:
				// パケットを書き込む
				_, err := tun.write(pkt.Buf[:pkt.N])
				if err != nil {
					log.Printf("write error: %s", err.Error())
				}
			}
		}
	}()
}
