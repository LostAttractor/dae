// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"cmp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/daeuniverse/dae/api"
)

const (
	maxScriptNotifications = 50
	maxNotificationText    = 1024
	maxNotificationBody    = 4096
	maxNotificationHistory = 1 << 20 // Conservative encoded JSON budget per instance.
)

// Runtime-owned: each script gets its own bounded history, shared by invocations.
// Rebuilding an instance creates a new history, independently of its file store.
type notificationHistory struct {
	mu      sync.Mutex
	scripts map[notificationScript]*scriptNotifications
	lastID  uint64
	bytes   int
}

type notificationScript struct {
	module, script, kind string
}

type scriptNotifications struct {
	entries []api.SurgeNotification
}

func notificationBytes(n api.SurgeNotification) int {
	// JSON can expand each text byte to a six-byte escape. Leave room for
	// field names, timestamps, IDs and separators without allocating JSON here.
	return 512 + 6*(len(n.Module)+len(n.Script)+len(n.ScriptType)+len(n.Title)+len(n.Subtitle)+len(n.Body))
}

func (h *notificationHistory) add(notification api.SurgeNotification) {
	// Key by the original, host-provided identity before truncating report text.
	key := notificationScript{notification.Module, notification.Script, notification.ScriptType}
	for _, field := range []*string{&notification.Module, &notification.Script, &notification.Title, &notification.Subtitle, &notification.Body} {
		limit := maxNotificationText
		if field == &notification.Body {
			limit = maxNotificationBody
		}
		if len(*field) > limit {
			// Preserve valid UTF-8 and release the potentially large input string.
			for limit > 0 && !utf8.RuneStart((*field)[limit]) {
				limit--
			}
			*field = strings.Clone((*field)[:limit])
			notification.Truncated = true
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastID++
	notification.ID, notification.CreatedAt = h.lastID, time.Now()
	if h.scripts == nil {
		h.scripts = make(map[notificationScript]*scriptNotifications)
	}
	history := h.scripts[key]
	if history == nil {
		history = &scriptNotifications{}
		h.scripts[key] = history
	}
	if len(history.entries) < maxScriptNotifications {
		history.entries = append(history.entries, notification)
	} else {
		h.bytes -= notificationBytes(history.entries[0])
		copy(history.entries, history.entries[1:])
		history.entries[len(history.entries)-1] = notification
	}
	h.bytes += notificationBytes(notification)
	for h.bytes > maxNotificationHistory {
		// Trim the longest history first; for ties, remove the oldest record.
		// Frequent writers therefore give up history before quieter scripts.
		var victim notificationScript
		var longest *scriptNotifications
		for key, candidate := range h.scripts {
			if longest == nil || len(candidate.entries) > len(longest.entries) ||
				len(candidate.entries) == len(longest.entries) && candidate.entries[0].ID < longest.entries[0].ID {
				victim, longest = key, candidate
			}
		}
		h.bytes -= notificationBytes(longest.entries[0])
		longest.entries[0] = api.SurgeNotification{}
		longest.entries = longest.entries[1:]
		if len(longest.entries) == 0 {
			delete(h.scripts, victim)
		}
	}
}

func (h *notificationHistory) snapshot() []api.SurgeNotification {
	h.mu.Lock()
	var notifications []api.SurgeNotification
	for _, history := range h.scripts {
		notifications = append(notifications, history.entries...)
	}
	h.mu.Unlock()
	slices.SortFunc(notifications, func(a, b api.SurgeNotification) int {
		return cmp.Compare(b.ID, a.ID)
	})
	return notifications
}
