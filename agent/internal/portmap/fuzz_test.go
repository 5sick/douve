package portmap

import (
	"encoding/xml"
	"testing"
)

// 공유기 기기 설명(XML)은 같은 망의 아무 기기나 SSDP로 보낼 수 있다
func FuzzDescription(f *testing.F) {
	f.Add([]byte(`<root><device><deviceList><device><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/c</controlURL></service></serviceList></device></deviceList></device></root>`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var root xmlRoot
		if xml.Unmarshal(b, &root) == nil {
			_, _ = findService(root.Device)
		}
		var fault soapFault
		_ = xml.Unmarshal(b, &fault)
	})
}
