package internal

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestComputeCRC24(t *testing.T) {

	testCases := map[string]struct {
		base64Data     string
		base64Checksum string
	}{
		"test 1": {
			`owGbwMvMwCWmemUby0pOLhXG02xJDElh7lM6prMwiHEx2IspsuS6azG8TdPdqnbA
diNMHSsTSJGiTF5+SVFqYg6QysjMS88sBnEcUisScwtyUvWS83MZuDgFYHokzBkZ
Xh98v+Db4fCcssPLvl38G2fbfeXfqo8VUlosKQENrxgbnzEy9J3MFnrivtiz3SY/
qv+Ky9E1ZXLnul5+tpgtHvijqGw/FwA=`,
			"noZm",
		},
		"test 2": {
			`yDgBO22WxBHv7O8X7O/jygAEzol56iUKiXmV+XmpCtmpqQUKiQrFqclFqUDBovzS
vBSFjNSiVHsuAA==`,
			"njUN",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			data, err := base64.StdEncoding.DecodeString(testCase.base64Data)
			require.NoError(t, err)
			checksum, err := base64.StdEncoding.DecodeString(testCase.base64Checksum)
			require.NoError(t, err)

			result := ComputeCRC24(data)

			assert.Equal(t, checksum, result)
		})
	}

}
