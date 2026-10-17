/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2017-2022 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

package main

// #cgo LDFLAGS: -llog
// #include <android/log.h>
import "C"

import (
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"unsafe"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/ipc"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.org/x/sys/unix"
)

type AndroidLogger struct {
	level C.int
	tag   *C.char
}

func cstring(s string) *C.char {
	b, err := unix.BytePtrFromString(s)
	if err != nil {
		b := [1]C.char{}
		return &b[0]
	}
	return (*C.char)(unsafe.Pointer(b))
}

func (l AndroidLogger) Printf(format string, args ...interface{}) {
	C.__android_log_write(l.level, l.tag, cstring(fmt.Sprintf(format, args...)))
}

type TunnelHandle struct {
	device *device.Device
	uapi   net.Listener
}

var tunnelHandles map[int32]TunnelHandle

func init() {
	tunnelHandles = make(map[int32]TunnelHandle)
	signals := make(chan os.Signal)
	signal.Notify(signals, unix.SIGUSR2)
	go func() {
		buf := make([]byte, os.Getpagesize())
		for {
			select {
			case <-signals:
				n := runtime.Stack(buf, true)
				if n == len(buf) {
					n--
				}
				buf[n] = 0
				C.__android_log_write(C.ANDROID_LOG_ERROR, cstring("AmneziaWG/Stacktrace"), (*C.char)(unsafe.Pointer(&buf[0])))
			}
		}
	}()
}

//export awgTurnOn
func awgTurnOn(interfaceName string, tunFd int32, settings string) int32 {
	tag := cstring("AmneziaWG/" + interfaceName)
	logger := &device.Logger{
		Verbosef: AndroidLogger{level: C.ANDROID_LOG_DEBUG, tag: tag}.Printf,
		Errorf:   AndroidLogger{level: C.ANDROID_LOG_ERROR, tag: tag}.Printf,
	}

	tun, name, err := tun.CreateUnmonitoredTUNFromFD(int(tunFd))
	if err != nil {
		unix.Close(int(tunFd))
		logger.Errorf("CreateUnmonitoredTUNFromFD: %v", err)
		return -1
	}

	logger.Verbosef("Attaching to interface %v", name)
	device := device.NewDevice(tun, conn.NewStdNetBind(), logger)

	err = device.IpcSet(settings)
	if err != nil {
		unix.Close(int(tunFd))
		logger.Errorf("IpcSet: %v", err)
		return -1
	}
	device.DisableSomeRoamingForBrokenMobileSemantics()

	var uapi net.Listener

	uapiFile, err := ipc.UAPIOpen(name)
	if err != nil {
		logger.Errorf("UAPIOpen: %v", err)
	} else {
		uapi, err = ipc.UAPIListen(name, uapiFile)
		if err != nil {
			uapiFile.Close()
			logger.Errorf("UAPIListen: %v", err)
		} else {
			go func() {
				for {
					conn, err := uapi.Accept()
					if err != nil {
						return
					}
					go device.IpcHandle(conn)
				}
			}()
		}
	}

	err = device.Up()
	if err != nil {
		logger.Errorf("Unable to bring up device: %v", err)
		uapiFile.Close()
		device.Close()
		return -1
	}
	logger.Verbosef("Device started")

	var i int32
	for i = 0; i < math.MaxInt32; i++ {
		if _, exists := tunnelHandles[i]; !exists {
			break
		}
	}
	if i == math.MaxInt32 {
		logger.Errorf("Unable to find empty handle")
		uapiFile.Close()
		device.Close()
		return -1
	}
	tunnelHandles[i] = TunnelHandle{device: device, uapi: uapi}
	return i
}

//export awgTurnOff
func awgTurnOff(tunnelHandle int32) {
	handle, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	delete(tunnelHandles, tunnelHandle)
	if handle.uapi != nil {
		handle.uapi.Close()
	}
	handle.device.Close()
}

//export awgGetSocketV4
func awgGetSocketV4(tunnelHandle int32) int32 {
	handle, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return -1
	}
	bind, _ := handle.device.Bind().(conn.PeekLookAtSocketFd)
	if bind == nil {
		return -1
	}
	fd, err := bind.PeekLookAtSocketFd4()
	if err != nil {
		return -1
	}
	return int32(fd)
}

//export awgGetSocketV6
func awgGetSocketV6(tunnelHandle int32) int32 {
	handle, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return -1
	}
	bind, _ := handle.device.Bind().(conn.PeekLookAtSocketFd)
	if bind == nil {
		return -1
	}
	fd, err := bind.PeekLookAtSocketFd6()
	if err != nil {
		return -1
	}
	return int32(fd)
}

//export awgGetConfig
func awgGetConfig(tunnelHandle int32) *C.char {
	handle, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return nil
	}
	settings, err := handle.device.IpcGet()
	if err != nil {
		return nil
	}
	return C.CString(settings)
}

// awgRequestHandshake asks every peer of the tunnel to start a new handshake now, instead of
// waiting for the device's own timers to notice that the session went quiet (KeepaliveTimeout plus
// RekeyTimeout, ~15 s). Returns the number of peers asked, or -1 if the handle is unknown or the
// device cannot be read.
//
// The current keypair is deliberately left alone: a caller that only suspects a stall must not
// cost a live tunnel a single packet, and a successful handshake replaces the keypair anyway.
// SendHandshakeInitiation rate-limits itself to once per RekeyTimeout, so calling this often is
// harmless — a call inside that window is a silent no-op, which is also why the result counts
// peers asked rather than handshakes sent.
//
//export awgRequestHandshake
func awgRequestHandshake(tunnelHandle int32) int32 {
	handle, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return -1
	}
	// The peer set is not exposed directly; the UAPI dump is the supported way to enumerate it,
	// and it is what getStatistics already parses on the Java side.
	settings, err := handle.device.IpcGet()
	if err != nil {
		return -1
	}
	var asked int32
	for _, line := range strings.Split(settings, "\n") {
		hexKey, found := strings.CutPrefix(line, "public_key=")
		if !found {
			continue
		}
		var key device.NoisePublicKey
		if key.FromHex(hexKey) != nil {
			continue
		}
		peer := handle.device.LookupPeer(key)
		if peer == nil {
			continue
		}
		// isRetry=false resets the attempt counter, so this counts as a fresh handshake rather
		// than as one more retry towards the device giving up on the peer.
		if peer.SendHandshakeInitiation(false) == nil {
			asked++
		}
	}
	return asked
}

//export awgVersion
func awgVersion() *C.char {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return C.CString("unknown")
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/amnezia-vpn/amneziawg-go/v3" {
			parts := strings.Split(dep.Version, "-")
			if len(parts) == 3 && len(parts[2]) == 12 {
				return C.CString(parts[2][:7])
			}
			return C.CString(dep.Version)
		}
	}
	return C.CString("unknown")
}

func main() {}
