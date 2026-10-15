package obfs

type constructor struct {
	New      func() IObfs
	Overhead int
}

var constructors = map[string]constructor{
	"plain":                  {New: newPlainObfs},
	"http_simple":            {New: newHttpSimple},
	"http_post":              {New: newHttpPost},
	"random_head":            {New: newRandomHead},
	"tls1.2_ticket_auth":     {New: func() IObfs { return newTLS12TicketAuth(false) }, Overhead: 5},
	"tls1.2_ticket_fastauth": {New: func() IObfs { return newTLS12TicketAuth(true) }, Overhead: 5},
}

type IObfs interface {
	SetServerInfo(s *ServerInfo)
	GetServerInfo() (s *ServerInfo)
	Encode(data []byte) (encodedData []byte, err error)
	Decode(data []byte) (decodedData []byte, needSendBack bool, err error)
}

type ServerInfo struct {
	Host  string
	Port  uint16
	Param string

	AddrLen int
	Key     []byte
	IVLen   int
}
