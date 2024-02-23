// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild
package codegen

import (
	"bytes"

	"github.com/kaitai-io/kaitai_struct_go_runtime/kaitai"
)

type Nanotdf_UrlProtocol int

const (
	Nanotdf_UrlProtocol__Http   Nanotdf_UrlProtocol = 0
	Nanotdf_UrlProtocol__Https  Nanotdf_UrlProtocol = 1
	Nanotdf_UrlProtocol__Shared Nanotdf_UrlProtocol = 255
)

type Nanotdf_EccMode int

const (
	Nanotdf_EccMode__Secp256r1 Nanotdf_EccMode = 0
	Nanotdf_EccMode__Secp384r1 Nanotdf_EccMode = 1
	Nanotdf_EccMode__Secp521r1 Nanotdf_EccMode = 2
	Nanotdf_EccMode__Secp256k1 Nanotdf_EccMode = 3
)

type Nanotdf_CipherMode int

const (
	Nanotdf_CipherMode__Aes256gcm64Bit  Nanotdf_CipherMode = 0
	Nanotdf_CipherMode__Aes256gcm96Bit  Nanotdf_CipherMode = 1
	Nanotdf_CipherMode__Aes256gcm104Bit Nanotdf_CipherMode = 2
	Nanotdf_CipherMode__Aes256gcm112Bit Nanotdf_CipherMode = 3
	Nanotdf_CipherMode__Aes256gcm120Bit Nanotdf_CipherMode = 4
	Nanotdf_CipherMode__Aes256gcm128Bit Nanotdf_CipherMode = 5
)

type Nanotdf struct {
	Header    *Nanotdf_Header
	Payload   *Nanotdf_Payload
	Signature *Nanotdf_NtdfSignature
	Length    uint64
	_io       *kaitai.Stream
	_root     *Nanotdf
	_parent   interface{}
}

func NewNanotdf() *Nanotdf {
	return &Nanotdf{}
}

func (this *Nanotdf) Read(io *kaitai.Stream, parent interface{}, root *Nanotdf) (err error) {
	this._io = io
	this._parent = parent
	this._root = root

	tmp1 := NewNanotdf_Header()
	err = tmp1.Read(this._io, this, this._root)
	if err != nil {
		return err
	}
	this.Header = tmp1
	this.Length = this.Length + this.Header.Length
	tmp2 := NewNanotdf_Payload()
	err = tmp2.Read(this._io, this, this._root)
	if err != nil {
		return err
	}
	this.Payload = tmp2
	this.Length = this.Length + this.Payload.Length + 3
	if this.Header.SigCfg.HasSignature {
		tmp3 := NewNanotdf_NtdfSignature()
		err = tmp3.Read(this._io, this, this._root)
		if err != nil {
			return err
		}
		this.Signature = tmp3
	}
	return err
}

type Nanotdf_BindingCfg struct {
	UseEcdsaBinding bool
	Padding         uint64
	BindingBody     Nanotdf_EccMode
	_io             *kaitai.Stream
	_root           *Nanotdf
	_parent         *Nanotdf_Header
}

func NewNanotdf_BindingCfg() *Nanotdf_BindingCfg {
	return &Nanotdf_BindingCfg{}
}

func (this *Nanotdf_BindingCfg) Read(io *kaitai.Stream, parent *Nanotdf_Header, root *Nanotdf) (err error) {
	this._io = io
	this._parent = parent
	this._root = root

	tmp4, err := this._io.ReadBitsIntBe(1)
	if err != nil {
		return err
	}
	this.UseEcdsaBinding = tmp4 != 0
	tmp5, err := this._io.ReadBitsIntBe(3)
	if err != nil {
		return err
	}
	this.Padding = tmp5
	tmp6, err := this._io.ReadBitsIntBe(4)
	if err != nil {
		return err
	}
	parent.Length = parent.Length + 8
	this.BindingBody = Nanotdf_EccMode(tmp6)
	return err
}

type Nanotdf_EccKey struct {
	Key     []byte
	_io     *kaitai.Stream
	_root   *Nanotdf
	_parent interface{}
}

func NewNanotdf_EccKey() *Nanotdf_EccKey {
	return &Nanotdf_EccKey{}
}

func (this *Nanotdf_EccKey) Read(io *kaitai.Stream, parent interface{}, root *Nanotdf) (err error) {
	this._io = io
	this._parent = parent
	this._root = root

	var tmp7 int8
	if this._root.Header.Binding.BindingBody == Nanotdf_EccMode__Secp256r1 {
		tmp7 = 32
	} else {
		var tmp8 int8
		if this._root.Header.Binding.BindingBody == Nanotdf_EccMode__Secp384r1 {
			tmp8 = 48
		} else {
			var tmp9 int8
			if this._root.Header.Binding.BindingBody == Nanotdf_EccMode__Secp521r1 {
				tmp9 = 66
			} else {
				tmp9 = 0
			}
			tmp8 = tmp9
		}
		tmp7 = tmp8
	}
	tmp10, err := this._io.ReadBytes(int(tmp7))
	if err != nil {
		return err
	}
	this._root.Header.Length = this._root.Header.Length + uint64(tmp7)
	this.Key = tmp10
	return err
}

type Nanotdf_EccSignature struct {
	Value   []byte
	_io     *kaitai.Stream
	_root   *Nanotdf
	_parent interface{}
}

func NewNanotdf_EccSignature() *Nanotdf_EccSignature {
	return &Nanotdf_EccSignature{}
}

func (this *Nanotdf_EccSignature) Read(io *kaitai.Stream, parent interface{}, root *Nanotdf) (err error) {
	this._io = io
	this._parent = parent
	this._root = root
	this._root.Header = parent.(*Nanotdf_Header)
	var tmp11 int8
	if this._root.Header.Binding.BindingBody == Nanotdf_EccMode__Secp256r1 {
		tmp11 = 32
	} else {
		var tmp12 int8
		if this._root.Header.Binding.BindingBody == Nanotdf_EccMode__Secp384r1 {
			tmp12 = 48
		} else {
			var tmp13 int8
			if this._root.Header.Binding.BindingBody == Nanotdf_EccMode__Secp521r1 {
				tmp13 = 66
			} else {
				tmp13 = 0
			}
			tmp12 = tmp13
		}
		tmp11 = tmp12
	}
	tmp14, err := this._io.ReadBytes(int(2 * tmp11))
	if err != nil {
		return err
	}
	this._root.Header.Length = this._root.Header.Length + uint64(2*tmp11)
	this.Value = tmp14
	return err
}

type Nanotdf_Payload struct {
	Length      uint64
	PayloadBody []byte
	_io         *kaitai.Stream
	_root       *Nanotdf
	_parent     *Nanotdf
}

func NewNanotdf_Payload() *Nanotdf_Payload {
	return &Nanotdf_Payload{}
}

func (this *Nanotdf_Payload) Read(io *kaitai.Stream, parent *Nanotdf, root *Nanotdf) (err error) {
	this._io = io
	this._parent = parent
	this._root = root

	tmp15, err := this._io.ReadBitsIntBe(24)
	if err != nil {
		return err
	}
	this.Length = tmp15
	this._io.AlignToByte()
	tmp16, err := this._io.ReadBytes(int(this.Length))
	if err != nil {
		return err
	}
	// tmp16 = tmp16
	this.PayloadBody = tmp16
	return err
}

type Nanotdf_ResourceLocator struct {
	Protocol Nanotdf_UrlProtocol
	Length   uint8
	Body     string
	_io      *kaitai.Stream
	_root    *Nanotdf
	_parent  interface{}
}

func NewNanotdf_ResourceLocator() *Nanotdf_ResourceLocator {
	return &Nanotdf_ResourceLocator{}
}

func (this *Nanotdf_ResourceLocator) Read(io *kaitai.Stream, parent interface{}, root *Nanotdf) (err error) {
	this._io = io
	this._parent = parent
	this._root = root

	tmp17, err := this._io.ReadU1()
	if err != nil {
		return err
	}
	this.Protocol = Nanotdf_UrlProtocol(tmp17)
	tmp18, err := this._io.ReadU1()
	if err != nil {
		return err
	}
	this.Length = tmp18
	tmp19, err := this._io.ReadBytes(int(this.Length))
	if err != nil {
		return err
	}
	this.Body = string(tmp19)
	return err
}

type Nanotdf_EmbeddedPolicy struct {
	Length  uint16
	Body    string
	_io     *kaitai.Stream
	_root   *Nanotdf
	_parent *Nanotdf_Policy
}

func NewNanotdf_EmbeddedPolicy() *Nanotdf_EmbeddedPolicy {
	return &Nanotdf_EmbeddedPolicy{}
}

func (this *Nanotdf_EmbeddedPolicy) Read(io *kaitai.Stream, parent *Nanotdf_Policy, root *Nanotdf) (err error) {
	this._io = io
	this._parent = parent
	this._root = root

	tmp20, err := this._io.ReadU2be()
	if err != nil {
		return err
	}
	this.Length = tmp20
	tmp21, err := this._io.ReadBytes(int(this.Length))
	if err != nil {
		return err
	}
	//tmp21 = tmp21
	this.Body = string(tmp21)
	return err
}

type Nanotdf_NtdfSignature struct {
	ClientKey       *Nanotdf_EccKey
	ClientSignature *Nanotdf_EccSignature
	_io             *kaitai.Stream
	_root           *Nanotdf
	_parent         *Nanotdf
}

func NewNanotdf_NtdfSignature() *Nanotdf_NtdfSignature {
	return &Nanotdf_NtdfSignature{}
}

func (this *Nanotdf_NtdfSignature) Read(io *kaitai.Stream, parent *Nanotdf, root *Nanotdf) (err error) {
	this._io = io
	this._parent = parent
	this._root = root

	tmp22 := NewNanotdf_EccKey()
	err = tmp22.Read(this._io, this, this._root)
	if err != nil {
		return err
	}
	this.ClientKey = tmp22
	tmp23 := NewNanotdf_EccSignature()
	err = tmp23.Read(this._io, this, this._root)
	if err != nil {
		return err
	}
	this.ClientSignature = tmp23
	return err
}

type Nanotdf_RemotePolicy struct {
	Url     *Nanotdf_ResourceLocator
	_io     *kaitai.Stream
	_root   *Nanotdf
	_parent *Nanotdf_Policy
}

func NewNanotdf_RemotePolicy() *Nanotdf_RemotePolicy {
	return &Nanotdf_RemotePolicy{}
}

func (this *Nanotdf_RemotePolicy) Read(io *kaitai.Stream, parent *Nanotdf_Policy, root *Nanotdf) (err error) {
	this._io = io
	this._parent = parent
	this._root = root

	tmp24 := NewNanotdf_ResourceLocator()
	err = tmp24.Read(this._io, this, this._root)
	if err != nil {
		return err
	}
	this.Url = tmp24
	return err
}

type Nanotdf_Header struct {
	Length             uint64
	Magic              []byte
	Kas                *Nanotdf_ResourceLocator
	Binding            *Nanotdf_BindingCfg
	SigCfg             *Nanotdf_SignatureConfig
	Policy             *Nanotdf_Policy
	EphemeralPublicKey *Nanotdf_EccKey
	_io                *kaitai.Stream
	_root              *Nanotdf
	_parent            *Nanotdf
}

func NewNanotdf_Header() *Nanotdf_Header {
	return &Nanotdf_Header{}
}

func (this *Nanotdf_Header) Read(io *kaitai.Stream, parent *Nanotdf, root *Nanotdf) (err error) {
	this._io = io
	this._parent = parent
	this._root = root

	tmp25, err := this._io.ReadBytes(3)
	if err != nil {
		return err
	}
	//this.Length = this.Length + 3 + 6 // FIXME
	this.Magic = tmp25
	if !(bytes.Equal(this.Magic, []uint8{76, 49, 76})) {
		return kaitai.NewValidationNotEqualError([]uint8{76, 49, 76}, this.Magic, this._io, "/types/header/seq/0")
	}
	tmp26 := NewNanotdf_ResourceLocator()
	err = tmp26.Read(this._io, this, this._root)
	if err != nil {
		return err
	}
	this.Kas = tmp26
	tmp27 := NewNanotdf_BindingCfg()
	err = tmp27.Read(this._io, this, this._root)
	if err != nil {
		return err
	}
	this.Binding = tmp27
	tmp28 := NewNanotdf_SignatureConfig()
	err = tmp28.Read(this._io, this, this._root)
	if err != nil {
		return err
	}
	this.SigCfg = tmp28
	tmp29 := NewNanotdf_Policy()
	err = tmp29.Read(this._io, this, this._root)
	if err != nil {
		return err
	}
	emb, ok := tmp29.Body.(*Nanotdf_EmbeddedPolicy)
	if ok {
		this.Length = this.Length + uint64(emb.Length)
	}
	this.Policy = tmp29
	tmp30 := NewNanotdf_EccKey()
	err = tmp30.Read(this._io, this, this._root)
	if err != nil {
		return err
	}
	this.EphemeralPublicKey = tmp30
	return err
}

type Nanotdf_SignatureConfig struct {
	HasSignature  bool
	SignatureMode Nanotdf_EccMode
	Cipher        Nanotdf_CipherMode
	_io           *kaitai.Stream
	_root         *Nanotdf
	_parent       *Nanotdf_Header
}

func NewNanotdf_SignatureConfig() *Nanotdf_SignatureConfig {
	return &Nanotdf_SignatureConfig{}
}

func (this *Nanotdf_SignatureConfig) Read(io *kaitai.Stream, parent *Nanotdf_Header, root *Nanotdf) (err error) {
	this._io = io
	this._parent = parent
	this._root = root

	tmp31, err := this._io.ReadBitsIntBe(1)
	if err != nil {
		return err
	}
	this.HasSignature = tmp31 != 0
	tmp32, err := this._io.ReadBitsIntBe(3)
	if err != nil {
		return err
	}
	this.SignatureMode = Nanotdf_EccMode(tmp32)
	tmp33, err := this._io.ReadBitsIntBe(4)
	if err != nil {
		return err
	}
	parent.Length = parent.Length + 8
	this.Cipher = Nanotdf_CipherMode(tmp33)
	return err
}

type Nanotdf_Policy struct {
	Mode    uint8
	Body    interface{}
	Binding *Nanotdf_EccSignature
	_io     *kaitai.Stream
	_root   *Nanotdf
	_parent *Nanotdf_Header
}

func NewNanotdf_Policy() *Nanotdf_Policy {
	return &Nanotdf_Policy{}
}

func (this *Nanotdf_Policy) Read(io *kaitai.Stream, parent *Nanotdf_Header, root *Nanotdf) (err error) {
	this._io = io
	this._parent = parent
	this._root = root

	tmp34, err := this._io.ReadU1()
	if err != nil {
		return err
	}
	this.Mode = tmp34
	switch this.Mode {
	case 0:
		tmp35 := NewNanotdf_RemotePolicy()
		err = tmp35.Read(this._io, this, this._root)
		if err != nil {
			return err
		}
		this.Body = tmp35
	case 1:
		tmp36 := NewNanotdf_EmbeddedPolicy()
		err = tmp36.Read(this._io, this, this._root)
		if err != nil {
			return err
		}
		this.Body = tmp36
	case 2:
		tmp37 := NewNanotdf_EmbeddedPolicy()
		err = tmp37.Read(this._io, this, this._root)
		if err != nil {
			return err
		}
		this.Body = tmp37
	case 3:
		tmp38 := NewNanotdf_EmbeddedPolicy()
		err = tmp38.Read(this._io, this, this._root)
		if err != nil {
			return err
		}
		this.Body = tmp38
	}
	tmp39 := NewNanotdf_EccSignature()
	err = tmp39.Read(this._io, this._parent, this._root)
	if err != nil {
		return err
	}
	this.Binding = tmp39
	return err
}
