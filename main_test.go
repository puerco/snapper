package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/release-utils/command"
)

const testBinary = "/home/urbano/httpd.back"

func TestLocateBinaries(t *testing.T) {
	p, err := locateBinaries(".", "name")
	require.NoError(t, err)
	require.NotNil(t, p)
	require.Len(t, p, 2)
	require.Equal(t, p[0], "test/dir/file/name")
}

func TestPatchBinary(t *testing.T) {
	require.NoError(t, command.New("cp", testBinary, testBinary+".sut").RunSilentSuccess())
	defer os.Remove(testBinary + ".sut")
	require.NoError(t, NewSnapper("/tmp").patchBinary(testBinary+".sut", 3599627, "HolaAmigo"))
}

func TestFindStringOffset(t *testing.T) {
	offset, err := NewSnapper("/tmp").findStringOffset(
		"<iframe src=\"https://giphy.com/embed/11tTNkNy1SdXGg",
		testBinary,
	)
	require.NoError(t, err)
	require.Equal(t, int64(3599627), offset)

	offset, err = NewSnapper("/").findStringOffset(
		"<oframe src=\"https://giphy.com/embed/11tTNkNy1SdXGg",
		testBinary,
	)
	require.NoError(t, err)
	require.Equal(t, int64(-1), offset)
}
