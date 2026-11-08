package netproxy

import "github.com/daeuniverse/dae/pkg/membuffer"

// DatagramMemory accounts owned packet allocations across ingress, setup,
// bridges, reply backlogs and transport queues, including overlapping reloads.
// Protocol reassembly, reliable stream buffers, idle pools and kernel buffers
// are separate. Transferring a reservation never allocates another payload.
var DatagramMemory = membuffer.NewBudget(8 << 20)

var (
	DropUploadMemory   = NewDrop("", DropUpload, "packet_memory_limit")
	DropDownloadMemory = NewDrop("", DropDownload, "packet_memory_limit")
)
