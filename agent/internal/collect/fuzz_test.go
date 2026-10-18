package collect

import "testing"

func FuzzParsers(f *testing.F) {
	f.Add("0100007F:1F90", "wg0\tpk\tpsk\t1.2.3.4:51820\t10.0.0.2/32\t1700000000\t10\t20\toff\n", "x.service loaded failed failed X\n")
	f.Fuzz(func(t *testing.T, addr, wg, units string) {
		if host, port, ok := decodeAddr(addr); ok && (port < 0 || port > 65535 || host == "") {
			t.Fatalf("잘못된 주소 해석: %q → %q %d", addr, host, port)
		}
		_ = parseWGDump(wg)
		_ = parseFailedUnits(units)
		_ = parseTimerTriggered(units)
	})
}
