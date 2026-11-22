//go:build floor_sysio && linux

package main

import "syscall"

func init() {
	work = func(in, out string) error {
		src, err := syscall.Open(in, syscall.O_RDONLY, 0)
		if err != nil {
			return err
		}
		defer syscall.Close(src)
		buf := make([]byte, 0, 4096)
		for {
			n, err := syscall.Read(src, buf[len(buf):cap(buf)])
			if err != nil {
				return err
			}
			if n == 0 {
				break
			}
			buf = buf[:len(buf)+n]
			if len(buf) == cap(buf) {
				buf = append(buf, 0)[:len(buf)]
			}
		}
		dst, err := syscall.Open(out, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		defer syscall.Close(dst)
		_, err = syscall.Write(dst, buf)
		return err
	}
}
