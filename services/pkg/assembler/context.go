package assembler

import "github.com/google/gopacket"

// Context implements reassembly.AssemblerContext
type Context struct {
	CaptureInfo gopacket.CaptureInfo
}

func (c *Context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}
