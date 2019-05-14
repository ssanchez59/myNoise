package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	log2 "log"
	net2 "net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time" // "unsafe"

	"github.com/perlin-network/noise/crypto/ed25519"
	"github.com/perlin-network/noise/examples/chat/messages"
	"github.com/perlin-network/noise/log"
	"github.com/perlin-network/noise/network"
	"github.com/perlin-network/noise/network/discovery"
	"github.com/perlin-network/noise/types/opcode"
)

type ChatPlugin struct{ *network.Plugin }

var mutex = &sync.Mutex{}

type blockchain struct {
	Blocks []network.Block
	State  map[string]int
}

func (state *ChatPlugin) Receive(ctx *network.PluginContext) error {
	switch msg := ctx.Message().(type) {
	case *messages.ChatMessage:
		//log.Info().Msgf("<%s> %s", ctx.Client().ID.Address, msg.Message)
		b1 := blockchain{
			Blocks: make([]network.Block, 0),
			State:  make(map[string]int),
		}

		if err := json.Unmarshal([]byte(msg.Message), &b1); err != nil {
			log2.Fatal(err)
		}

		mutex.Lock()
		if len(b1.Blocks) > len(ctx.Network().Blockchain.Blocks) {
			ctx.Network().Blockchain.Blocks = b1.Blocks
			ctx.Network().Blockchain.State = b1.State

			bytes, err := json.MarshalIndent(ctx.Network().Blockchain, "", "  ")
			if err != nil {

				log2.Fatal(err)
			}
			// Green console color: 	\x1b[32m
			// Reset console color: 	\x1b[0m
			fmt.Printf("\x1b[32m%s\x1b[0m> ", string(bytes))
		}
		mutex.Unlock()

		//Latency test
		// fmt.Println("# Transactions: ", len(ctx.Network().Blockchain.Blocks))
		// lastBlock := ctx.Network().Blockchain.Blocks[len(ctx.Network().Blockchain.Blocks)-1]
		// elapsed := time.Since(lastBlock.TimeSent)
		// log.Printf("Latency: %s", elapsed)

	}
	return nil
}

func main() {
	// process other flags
	portFlag := flag.Int("port", 3000, "port to listen to")
	hostFlag := flag.String("host", getOutboundIP(), "host to listen to")
	protocolFlag := flag.String("protocol", "tcp", "protocol to use (kcp/tcp)")
	peersFlag := flag.String("peers", "", "peers to connect to")
	flag.Parse()

	port := uint16(*portFlag)
	host := *hostFlag
	protocol := *protocolFlag
	peers := strings.Split(*peersFlag, ",")

	keys := ed25519.RandomKeyPair()

	// log.Info().Msgf("Private Key: %s", keys.PrivateKeyHex())
	// log.Info().Msgf("Public Key: %s", keys.PublicKeyHex())

	opcode.RegisterMessageType(opcode.Opcode(1000), &messages.ChatMessage{})
	builder := network.NewBuilder()
	builder.SetKeys(keys)
	builder.SetAddress(network.FormatAddress(protocol, host, port))

	// Register peer discovery plugin.
	builder.AddPlugin(new(discovery.Plugin))

	// Add custom chat plugin.
	builder.AddPlugin(new(ChatPlugin))

	net, err := builder.Build("blockchain")
	if err != nil {
		log.Fatal().Err(err)
		return
	}

	go net.Listen()

	if len(peers) > 0 {
		net.Bootstrap(peers...)
	}

	// Tests
	// if net.Address == "tcp://10.150.0.2:3000" {

	// 	fmt.Print("Press 'Enter' to continue...")
	// 	bufio.NewReader(os.Stdin).ReadBytes('\n')

	// 	// // Throughput Test
	// 	// timer := time.NewTimer(time.Second)

	// 	// done := false
	// 	// go func() {
	// 	// 	<-timer.C
	// 	// 	done = true
	// 	// }()

	// 	// for !done {
	// 	// 	amountInt := 10

	// 	// 	from := "Bob"
	// 	// 	to := "Alice"

	// 	// 	net.Blockchain.State[from] = net.Blockchain.State[from] - amountInt
	// 	// 	net.Blockchain.State[to] = net.Blockchain.State[to] + amountInt

	// 	// 	newBlock := generateBlock(net.Blockchain.Blocks[len(net.Blockchain.Blocks)-1], "send 10 from Bob to Alice", net.Address, time.Time{})

	// 	// 	if isBlockValid(newBlock, net.Blockchain.Blocks[len(net.Blockchain.Blocks)-1]) {
	// 	// 		mutex.Lock()
	// 	// 		net.Blockchain.Blocks = append(net.Blockchain.Blocks, newBlock)
	// 	// 		mutex.Unlock()
	// 	// 	}

	// 	// 	bytes, err := json.Marshal(net.Blockchain)
	// 	// 	if err != nil {
	// 	// 		log2.Println(err)
	// 	// 	}

	// 	// 	ctx := network.WithSignMessage(context.Background(), true)
	// 	// 	net.Broadcast(ctx, &messages.ChatMessage{Message: string(bytes)})
	// 	// }

	// 	// Latency Test
	// 	// for i := 0; i < 50; i++ {

	// 	// 	timeSent := time.Now()

	// 	// 	amountInt := 10

	// 	// 	from := "Bob"
	// 	// 	to := "Alice"

	// 	// 	net.Blockchain.State[from] = net.Blockchain.State[from] - amountInt
	// 	// 	net.Blockchain.State[to] = net.Blockchain.State[to] + amountInt

	// 	// 	newBlock := generateBlock(net.Blockchain.Blocks[len(net.Blockchain.Blocks)-1], "send 10 from Bob to Alice", net.Address, timeSent)

	// 	// 	if isBlockValid(newBlock, net.Blockchain.Blocks[len(net.Blockchain.Blocks)-1]) {
	// 	// 		mutex.Lock()
	// 	// 		net.Blockchain.Blocks = append(net.Blockchain.Blocks, newBlock)
	// 	// 		mutex.Unlock()
	// 	// 	}

	// 	// 	bytes, err := json.Marshal(net.Blockchain)
	// 	// 	if err != nil {
	// 	// 		log2.Println(err)
	// 	// 	}

	// 	// 	ctx := network.WithSignMessage(context.Background(), true)
	// 	// 	net.Broadcast(ctx, &messages.ChatMessage{Message: string(bytes)})
	// 	// }
	// }

	//Size Tests
	// fmt.Println("Size of Block:  ", unsafe.Sizeof(net.Blockchain.Blocks[0]))

	reader := bufio.NewReader(os.Stdin)

	for {
		input, _ := reader.ReadString('\n')

		// skip blank lines
		if len(strings.TrimSpace(input)) == 0 {
			continue
		}

		ss := strings.Fields(input)

		amountString := ss[1]
		amountInt, err := strconv.Atoi(amountString)
		if err != nil {
			log2.Fatal(err)
		}

		from := ss[3]
		to := ss[5]

		net.Blockchain.State[from] = net.Blockchain.State[from] - amountInt
		net.Blockchain.State[to] = net.Blockchain.State[to] + amountInt

		newBlock := generateBlock(net.Blockchain.Blocks[len(net.Blockchain.Blocks)-1], input, net.Address, time.Now())

		// if isBlockValid(newBlock, net.Blockchain.Blocks[len(net.Blockchain.Blocks)-1]) {
		// 	mutex.Lock()
		// 	net.Blockchain.Blocks = append(net.Blockchain.Blocks, newBlock)
		// 	mutex.Unlock()
		// }

		net.Blockchain.Blocks = append(net.Blockchain.Blocks, newBlock)

		bytes, err := json.Marshal(net.Blockchain)
		if err != nil {
			log2.Println(err)
		}

		ctx := network.WithSignMessage(context.Background(), true)
		net.Broadcast(ctx, &messages.ChatMessage{Message: string(bytes)})
	}

}

func getOutboundIP() string {
	conn, err := net2.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log2.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net2.UDPAddr)

	return localAddr.IP.String()
}

// create a new block using previous block's hash
func generateBlock(oldBlock network.Block, Transaction string, address string, timeSent time.Time) network.Block {

	var newBlock network.Block

	t := time.Now()
	newBlock.Timestamp = time.Unix(0, t.UnixNano()).String()

	newBlock.Index = oldBlock.Index + 1
	newBlock.Transaction = Transaction
	newBlock.PrevHash = oldBlock.Hash
	newBlock.Signature = address
	newBlock.TimeSent = timeSent

	newBlock.Hash = calculateHash(newBlock)

	// for i := 0; ; i++ {
	// 	if !isHashValid(calculateHash(newBlock), 0) {
	// 		//fmt.Println(calculateHash(newBlock), " do more work!")
	// 		time.Sleep(time.Second)
	// 		continue
	// 	} else {
	// 		//fmt.Println(calculateHash(newBlock), " work done!")
	// 		newBlock.Hash = calculateHash(newBlock)
	// 		break
	// 	}
	// }

	return newBlock
}

func isHashValid(hash string, difficulty int) bool {
	prefix := strings.Repeat("0", difficulty)
	return strings.HasPrefix(hash, prefix)
}

// SHA256 hashing
func calculateHash(block network.Block) string {
	record := strconv.Itoa(block.Index) + block.Timestamp + block.PrevHash + block.Signature
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

// Make sure block is valid by checking index, comparing the hash of the previous block, and veryfying hash
func isBlockValid(newBlock, oldBlock network.Block) bool {
	if oldBlock.Index+1 != newBlock.Index {
		return false
	}

	if oldBlock.Hash != newBlock.PrevHash {
		return false
	}

	if calculateHash(newBlock) != newBlock.Hash {
		return false
	}

	return true
}
