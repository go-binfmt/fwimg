//go:build floor_sysio && linux

package main

import "syscall"

func init() {
	work = func(in, out string, n int) (int, int, error) {
		src, err := syscall.Open(in, syscall.O_RDONLY, 0)
		if err != nil {
			return 0, 0, err
		}
		defer syscall.Close(src)
		buf := make([]byte, 0, 4096)
		for {
			got, err := syscall.Read(src, buf[len(buf):cap(buf)])
			if err != nil {
				return 0, 0, err
			}
			if got == 0 {
				break
			}
			buf = buf[:len(buf)+got]
			if len(buf) == cap(buf) {
				buf = append(buf, 0)[:len(buf)]
			}
		}
		w, err := shape(buf, n)
		if err != nil {
			return len(buf), 0, err
		}
		dst, err := syscall.Open(out, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_TRUNC, 0o644)
		if err != nil {
			return len(buf), 0, err
		}
		defer syscall.Close(dst)
		wn, err := syscall.Write(dst, w)
		return len(buf), wn, err
	}
}
