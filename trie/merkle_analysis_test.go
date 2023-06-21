package trie

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/olekukonko/tablewriter"
	"os"
	"strconv"
	"testing"
)

var valWith32bytes = crypto.Keccak256Hash([]byte("valWith32bytes")).Bytes()

type Item struct {
	key []byte
	val []byte
}

// attention: verkle tree must 32 bytes len
var simpleDataWith4Item = []string{
	"a711355f",
	"a77d337f",
	"a7f9365f",
	"a77d397f",
}

var simpleDataWith7Level = []string{
	"1010d0ce",
	"1010df2a",
	"1010dfec",
	"101ea21e",
	"10e21aef",
	"1dac20ef",
	"e141acef",
	"e107efef",
}

var randomSize = flag.Int("randomSize", 1000, "set randomDataItem size")

func TestSimpleMerkleTree(t *testing.T) {
	items := generateItems(simpleDataWith4Item)
	analysisMerkle(items)
}

func TestSparseMerkleTree(t *testing.T) {
	items := generateItems(simpleDataWith7Level)
	analysisMerkle(items)
}

func generateItems(input []string) []Item {
	items := make([]Item, len(input))
	for i, s := range input {
		src := DecodeString(s)
		key := make([]byte, 32)
		if len(src) > len(key) {
			copy(key, src[:32])
		} else {
			copy(key, src)
			for j := len(src); j < len(key); j++ {
				key[j] = 0xff
			}
		}
		items[i] = Item{
			key: key,
			val: valWith32bytes,
		}
	}
	return items
}

func TestRandomMerkleTree(t *testing.T) {
	randomDataItem := randomKVList(*randomSize)
	fmt.Println("generated", *randomSize, "kv...")
	analysisMerkle(randomDataItem)
}

func analysisMerkle(input []Item) {
	diskdb := memorydb.New()
	triedb := NewDatabase(diskdb)
	root, _ := New(common.Hash{}, triedb)
	for _, item := range input {
		if err := root.TryUpdate(item.key, item.val); err != nil {
			panic(err)
		}
	}

	data := make(map[int][]int)
	scanMerkleTree(root.root, data, 0)
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Level", "FullNode", "ShortNode", "Value"})
	for i := 0; i < len(data); i++ {
		d := data[i]
		if len(d) == 0 {
			table.Append([]string{strconv.Itoa(i), "0", "0", "0"})
			continue
		}
		table.Append([]string{strconv.Itoa(i), strconv.Itoa(d[0]), strconv.Itoa(d[1]), strconv.Itoa(d[2])})
	}
	table.Render()

	// if size > 1000, only output max 100 per level
	nodeCache := make(map[int]int)
	for _, item := range input {
		level := getMerkleNodeLevel(root.root, keybytesToHex(item.key), 0, 0)
		if len(input) > 1000 && nodeCache[level] > 100 {
			continue
		}
		nodeCache[level] += 1
		proofDB := memorydb.New()
		if err := root.Prove(item.key, 0, proofDB); err != nil {
			panic(err)
		}
		fmt.Println("key:", hex.EncodeToString(item.key), "level:", level, "proof:", memdbSizeCount(proofDB))
	}

	// commit
	next, _, err := root.Commit(nil)
	if err != nil {
		panic(err)
	}
	err = triedb.Commit(next, true, nil)
	if err != nil {
		panic(err)
	}
	fmt.Println("trieStorageSize:", memdbSizeCount(diskdb))
}

func getMerkleNodeLevel(origNode node, path []byte, pos, depth int) int {
	// Path still needs to be traversed, descend into children
	switch n := (origNode).(type) {
	case *shortNode:
		if len(path)-pos < len(n.Key) || !bytes.Equal(n.Key, path[pos:pos+len(n.Key)]) {
			// Path branches off from short node
			return -1
		}
		if _, ok := n.Val.(valueNode); ok {
			return depth
		}

		return getMerkleNodeLevel(n.Val, path, pos+len(n.Key), depth+1)
	case *fullNode:
		return getMerkleNodeLevel(n.Children[path[pos]], path, pos+1, depth+1)
	case hashNode:
		panic("got hash node")
	case valueNode:
	default:
	}

	return -1
}

var (
	MerkleFullNodeIdx  = 0
	MerkleShortNodeIdx = 1
	MerkleValueNodeIdx = 2
)

func scanMerkleTree(src node, data map[int][]int, depth int) {
	if data[depth] == nil {
		data[depth] = []int{0, 0, 0}
	}

	switch n := src.(type) {
	case hashNode:
		panic("there have hash node")
	case *shortNode:
		data[depth][MerkleShortNodeIdx] += 1
		if _, ok := n.Val.(valueNode); ok {
			data[depth][MerkleValueNodeIdx] += 1
			return
		}
		scanMerkleTree(n.Val, data, depth+1)
	case *fullNode:
		data[depth][MerkleFullNodeIdx] += 1
		if _, ok := n.Children[16].(valueNode); ok {
			data[depth][MerkleValueNodeIdx] += 1
			return
		}
		for i := 0; i < 16; i++ {
			scanMerkleTree(n.Children[i], data, depth+1)
		}
	case valueNode:
	default: // It should be an UknonwnNode.
	}
}

func memdbSizeCount(memdb *memorydb.Database) int {
	size := 0
	iter := memdb.NewIterator(nil, nil)
	for iter.Next() {
		size += len(iter.Key())
		size += len(iter.Value())
	}
	iter.Release()
	return size
}

func randomKVList(num int) []Item {
	origin := make([]byte, 32)
	_, err := rand.Read(origin)
	if err != nil {
		panic(err)
	}

	ret := make([]Item, num)
	for i := 0; i < num; i++ {
		ret[i] = Item{
			key: crypto.Keccak256Hash(origin, []byte(strconv.Itoa(i))).Bytes(),
			val: valWith32bytes,
		}
	}

	return ret
}

func DecodeString(str string) []byte {
	ret, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}
	return ret
}
