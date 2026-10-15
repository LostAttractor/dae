package obfs

type plain struct {
	ServerInfo
}

func newPlainObfs() IObfs {
	p := &plain{}
	return p
}

func (p *plain) SetServerInfo(s *ServerInfo) {
	p.ServerInfo = *s
}

func (p *plain) GetServerInfo() (s *ServerInfo) {
	return &p.ServerInfo
}

func (p *plain) Encode(data []byte) (encodedData []byte, err error) {
	return data, nil
}

func (p *plain) Decode(data []byte) (decodedData []byte, needSendBack bool, err error) {
	return data, false, nil
}
