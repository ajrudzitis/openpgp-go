package openpgp_go

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"openpgp-go/internal"
	"regexp"
	"sort"
	"strings"
)

type BlockType string

const (
	PgpMessage    BlockType = "PGP MESSAGE"
	PgpPublicKey  BlockType = "PGP PUBLIC KEY"
	PgpPrivateKey BlockType = "PGP PRIVATE KEY"
	PgpSignature  BlockType = "PGP SIGNATURE"
)

var headerLineRegex = regexp.MustCompile("-----BEGIN (?P<block>PGP [A-Z ]+)-----")
var footerLineRegex = regexp.MustCompile("-----END (?P<block>PGP [A-Z ]+)-----")
var headerRegex = regexp.MustCompile("([[:ascii:]]+): ([[:ascii:]]+)")
const maxLineSize = 64

type Block struct {
	Type     BlockType
	Headers  map[string]string
	Contents *bytes.Buffer
}

func Armor(blocks ...Block) (*bytes.Buffer, error) {
	output := new(bytes.Buffer)

	for _, block := range blocks {
		err := block.armor(output)
		if err != nil {
			return nil, err
		}
	}

	return output, nil
}

func (b *Block) armor(output *bytes.Buffer) error {
	// write the header line
	_, err := output.WriteString(fmt.Sprintf("-----BEGIN %s-----\n", string(b.Type)))
	if err != nil {
		return err
	}

	// write out the headers
	keys := make([]string, 0, len(b.Headers))
	for k := range b.Headers {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	for _, k := range keys {
		_, err = output.WriteString(fmt.Sprintf("%s: %s\n", k, b.Headers[k]))
		if err != nil {
			return err
		}
	}

	output.WriteString("\n")

	// write out the body
	base64Body := base64.StdEncoding.EncodeToString(b.Contents.Bytes())
	for {
		var nextLine string
		if len(base64Body) > maxLineSize {
			nextLine = base64Body[0:maxLineSize]
			base64Body = base64Body[maxLineSize:]
		} else {
			nextLine = base64Body
			base64Body = ""
		}

		_, err = output.WriteString(nextLine + "\n")
		if err != nil {
			return err
		}

		if len(base64Body) <= 0 {
			break
		}
	}

	// write the checksum
	checksum := internal.ComputeCRC24(b.Contents.Bytes())
	checksumBase64 := base64.StdEncoding.EncodeToString(checksum)
	_, err = output.WriteString(fmt.Sprintf("=%s\n", checksumBase64))
	if err != nil {
		return err
	}

	// write the footer line
	_, err = output.WriteString(fmt.Sprintf("-----END %s-----\n", string(b.Type)))
	if err != nil {
		return err
	}

	return nil
}

func Dearmor(input io.Reader) ([]Block, error) {
	var blocks []Block
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		if match := headerLineRegex.FindStringSubmatch(scanner.Text()); match != nil {
			blockTypeString := match[1]
			blockType, err := parseBlockType(blockTypeString)
			if err != nil {
				return nil, err
			}
			newBlock, err := parseBlock(scanner, blockType)
			if err != nil {
				return nil, err
			}
			blocks = append(blocks, *newBlock)
		}
	}
	return blocks, nil
}

func parseBlockType(name string) (BlockType, error) {
	switch name {
	case string(PgpMessage):
		return PgpMessage, nil
	case string(PgpPublicKey):
		return PgpPublicKey, nil
	case string(PgpPrivateKey):
		return PgpPrivateKey, nil
	case string(PgpSignature):
		return PgpSignature, nil
	default:
		return "", fmt.Errorf("armor: unsupported block type: %s", name)
	}
}

func parseBlock(scanner *bufio.Scanner, blockType BlockType) (*Block, error) {
	// because the block type is determined outside this function, we're already past
	// the Dearmor Header Line
	headers := make(map[string]string)

	// read any headers
	for scanner.Scan() {
		line := scanner.Text()

		if match := headerRegex.FindStringSubmatch(line); match != nil {
			key := match[1]
			value := match[2]
			headers[key] = value
		}

		// the headers are terminated by a blank line
		if line == "" {
			break
		}
	}

	// read the base64 encoded body
	// this is slightly complicated, because we need to read to the end, and then keep the last line of the body
	// as the checksum

	var base64Body, maybeChecksum string
	for scanner.Scan() {
		line := scanner.Text()
		if match := footerLineRegex.FindStringSubmatch(line); match != nil {
			endBlockTypeString := match[1]

			// verify the block was closed with the correct type
			if endBlockTypeString != string(blockType) {
				return nil, fmt.Errorf("armor: closing block type does not match: expected %s, received %s", blockType, endBlockTypeString)
			}

			// break here, keeping the maybeChecksum value
			break
		}

		// if this is not the end, maybe this is the checksum before the end
		base64Body += maybeChecksum
		maybeChecksum = line
	}

	body, err := base64.StdEncoding.DecodeString(base64Body)
	if err != nil {
		return nil, fmt.Errorf("armor: error decoding base64 body: %w", err)
	}

	checksumString := strings.TrimPrefix(maybeChecksum, "=")
	checksum, err := base64.StdEncoding.DecodeString(checksumString)
	if err != nil {
		return nil, fmt.Errorf("armor: error decoding checksum: %w", err)
	}

	err = verifyChecksum(body, checksum)
	if err != nil {
		return nil, err
	}

	return &Block{
		Type:     blockType,
		Headers:  headers,
		Contents: bytes.NewBuffer(body),
	}, nil
}

func verifyChecksum(data []byte, expected []byte) error {
	checksum := internal.ComputeCRC24(data)
	if bytes.Compare(checksum, expected) != 0 {
		return fmt.Errorf("armor: checksum does not match: expected %s but got %s", hex.EncodeToString(expected), hex.EncodeToString(checksum))
	}
	return nil
}
