package outbound

import (
	"context"
	"fmt"
	"net/netip"
)

func (w *Masque) startDevice(ctx context.Context) error {
	w.deviceMutex.Lock()
	defer w.deviceMutex.Unlock()
	if err := w.runCtx.Err(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if w.runDevice {
		return nil
	}
	device := w.tunDevice
	if device == nil {
		var err error
		device, err = newIPStack(w.option.IPStack, w.localPrefixes, uint32(w.option.MTU))
		if err != nil {
			return fmt.Errorf("create device: %w", err)
		}
		defer func() {
			if !w.runDevice {
				_ = device.Close()
			}
		}()
	}
	if err := w.runCtx.Err(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := device.Start(); err != nil {
		return err
	}
	w.tunDevice, w.runDevice = device, true
	if err := w.runCtx.Err(); err != nil {
		return err
	}
	return ctx.Err()
}

// Unusual inputs still go through the selected backend's constructor so its
// validation errors remain configuration errors instead of first-dial errors.
func ipStackNeedsEagerValidation(prefixes []netip.Prefix, mtu uint32) bool {
	if mtu != 0 && (mtu < 68 || mtu > 65535) {
		return true
	}
	for i, prefix := range prefixes {
		address := prefix.Addr().Unmap()
		if !prefix.IsValid() || !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.Zone() != "" {
			return true
		}
		bits := prefix.Bits()
		if prefix.Addr().Is6() && address.Is4() {
			bits -= 96
		}
		if bits < 0 || bits > address.BitLen() || address.Is6() && mtu != 0 && mtu < 1280 {
			return true
		}
		for j, other := range prefixes {
			if i != j && prefix.Addr() == other.Addr() {
				return true
			}
			if !address.Is4() || !other.Addr().Unmap().Is4() {
				continue
			}
			otherBits := other.Bits()
			if other.Addr().Is6() {
				otherBits -= 96
			}
			if otherBits < 0 || otherBits > 32 {
				return true
			}
			network := netip.PrefixFrom(other.Addr().Unmap(), otherBits).Masked()
			if network.Contains(address) && ipStackIPv4Broadcast(address, otherBits) {
				return true
			}
		}
	}
	return false
}

func ipStackIPv4Broadcast(address netip.Addr, bits int) bool {
	value := address.As4()
	all := uint32(value[0])<<24 | uint32(value[1])<<16 | uint32(value[2])<<8 | uint32(value[3])
	if all == ^uint32(0) {
		return true
	}
	if bits >= 31 {
		return false
	}
	hostMask := uint32((uint64(1) << (32 - bits)) - 1)
	return all&hostMask == hostMask
}
