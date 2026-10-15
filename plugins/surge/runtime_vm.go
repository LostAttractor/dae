// SPDX-License-Identifier: AGPL-3.0-only

package surge

type scriptVM interface {
	SetHostFunc(func([]string) (any, error)) error
	SetInputJSON([]byte) error
	Bootstrap() error
	Eval(string) error
	Dispatch(int, string) error
	ExecutePendingJobs() error
	Close()
}
