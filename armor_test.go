package openpgp_go

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestArmor(t *testing.T) {

	testCases := map[string]struct {
		input            string
		expectedHeaders  map[string]string
		expectedContents []byte
		expectedError    string
	}{
		"rfc sample": {
			input: `-----BEGIN PGP MESSAGE-----
Version: OpenPrivacy 0.99

yDgBO22WxBHv7O8X7O/jygAEzol56iUKiXmV+XmpCtmpqQUKiQrFqclFqUDBovzS
vBSFjNSiVHsuAA==
=njUN
   -----END PGP MESSAGE-----`,
			expectedContents: mustBase64Decode(t, "yDgBO22WxBHv7O8X7O/jygAEzol56iUKiXmV+XmpCtmpqQUKiQrFqclFqUDBovzSvBSFjNSiVHsuAA=="),
			expectedHeaders: map[string]string{
				"Version": "OpenPrivacy 0.99",
			},
		},
		"rfc sample - wrong checksum": {
			input: `-----BEGIN PGP MESSAGE-----
Version: OpenPrivacy 0.99

yDgBO22WxBHv7O8X7O/jygAEzol56iUKiXmV+XmpCtmpqQUKiQrFqclFqUDBovzS
vBSFjNSiVHsuAA==
=nxUN
   -----END PGP MESSAGE-----`,
			expectedError: "armor: checksum does not match: expected 9f150d but got 9e350d",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			tc := testCase
			blocks, err := Dearmor(strings.NewReader(tc.input))
			if tc.expectedError != "" {
				assert.ErrorContains(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				require.Equal(t, len(blocks), 1)
				assert.Equal(t, tc.expectedContents, blocks[0].Contents.Bytes())
				assert.Equal(t, tc.expectedHeaders, blocks[0].Headers)
			}
		})
	}

}

func mustBase64Decode(t *testing.T, s string) []byte {
	t.Helper()

	b, err := base64.StdEncoding.DecodeString(s)
	require.NoError(t, err)

	return b
}
