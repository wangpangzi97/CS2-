package entitycodec

import (
	"crypto/sha256"
	"fmt"
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
)

// Closed registry: no ranges, guessed versions, class-count-only acceptance or
// configurable wire schemas. Provenance is recorded in validated_profiles.json.
type validatedProfile struct {
	protocol int32
	build    int32
}

func entityProfile(protocol, classes int32) (validatedProfile, bool) {
	if classes != 222 {
		return validatedProfile{}, false
	}
	switch protocol {
	case 14191:
		return validatedProfile{14191, 10924}, true
	case 14192:
		return validatedProfile{14192, 10955}, true
	default:
		return validatedProfile{}, false
	}
}
func profileLabel(info *msg.CSVCMsg_ServerInfo) string {
	p, ok := entityProfile(info.GetProtocol(), info.GetMaxClasses())
	if !ok {
		return "unsupported"
	}
	return fmt.Sprintf("%d/build%d", p.protocol, p.build)
}
func profileSource(info *msg.CSVCMsg_ServerInfo) string {
	p, ok := entityProfile(info.GetProtocol(), info.GetMaxClasses())
	if !ok {
		return "unsupported"
	}
	return fmt.Sprintf("packet_entities/profile%d-build%d", p.protocol, p.build)
}
func verifyProfileAssets() error {
	expected := map[string]string{
		"assets/sendtables.bin": "25e6ad5a3c022b30fc6eb60fb8b769f5532dd7071ced9d93008675d74c747e14",
		"assets/classinfo.pb":   "a4fb437a42e128cc1eaf71a0e5f81148e37213e9908b0a586d9866f52f5daa46",
	}
	for name, want := range expected {
		b, e := assets.ReadFile(name)
		if e != nil {
			return e
		}
		if fmt.Sprintf("%x", sha256.Sum256(b)) != want {
			return fmt.Errorf("validated entity schema asset mismatch")
		}
	}
	return nil
}
