package common

import (
	"time"
	"weak"
)

// release must not capture owner or session; pass a method expression instead.
func AfterGrace[O, S any](delay time.Duration, owner *O, session *S, release func(*O, *S)) *time.Timer {
	ownerRef, sessionRef := weak.Make(owner), weak.Make(session)
	return time.AfterFunc(delay, func() {
		owner, session := ownerRef.Value(), sessionRef.Value()
		if owner != nil && session != nil {
			release(owner, session)
		}
	})
}
