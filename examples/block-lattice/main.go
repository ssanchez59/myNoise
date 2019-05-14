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
	"sync" // "unsafe"
	"time"

	"github.com/perlin-network/noise/crypto/ed25519"
	"github.com/perlin-network/noise/examples/chat/messages"
	"github.com/perlin-network/noise/log"
	"github.com/perlin-network/noise/network"
	"github.com/perlin-network/noise/network/discovery"
	"github.com/perlin-network/noise/types/opcode"
)

type ChatPlugin struct{ *network.Plugin }

var mutex = &sync.Mutex{}

var cube network.Cube

func (state *ChatPlugin) Receive(ctx *network.PluginContext) error {
	switch msg := ctx.Message().(type) {
	case *messages.ChatMessage:
		//log.Info().Msgf("<%s> %s", ctx.Client().ID.Address, "Received: "+msg.Message)

		cube := network.Cube{}

		if err := json.Unmarshal([]byte(msg.Message), &cube); err != nil {
			log2.Fatal(err)
		}

		//update lattice for sender
		mutex.Lock()
		owner := cube.Signature
		ctx.Network().Lattice[owner] = append(ctx.Network().Lattice[owner], cube)
		mutex.Unlock()

		//update lattice for receiver
		receiver := cube.Receiver
		if ctx.Network().Address == receiver {
			mutex.Lock()
			receiveChain := ctx.Network().Lattice[receiver]
			//generateCube(oldCube, typeOfTransaction, amount, signature, hash, timeSent, sender, receiver)
			receiveCube := generateCube(receiveChain[len(receiveChain)-1], "receive", cube.Amount, receiver, " ", cube.TimeSent, cube.Sender, cube.Receiver)
			receiveCube.Source = cube.Hash
			receiveChain = append(receiveChain, receiveCube)
			ctx.Network().Lattice[receiver] = receiveChain
			mutex.Unlock()

			r, err := json.Marshal(receiveCube)
			if err != nil {
				fmt.Println("error:", err)
			}

			ctx2 := network.WithSignMessage(context.Background(), true)
			ctx.Network().Broadcast(ctx2, &messages.ChatMessage{Message: string(r)})
		}

		// if cube.Type == "receive" {

		// 	//Latency test
		// 	fmt.Println("# Transactions: ", len(ctx.Network().Lattice[receiver]))

		// 	elapsed := time.Since(cube.TimeSent)
		// 	log.Printf("Latency: %s", elapsed)

		// 	//Print lattice
		// 	// b, err := json.MarshalIndent(ctx.Network().Lattice, "", "  ")
		// 	// if err != nil {
		// 	// 	fmt.Println("error:", err)
		// 	// }
		// 	// fmt.Print(string(b))
		// }

		// Print lattice
		b, err := json.MarshalIndent(ctx.Network().Lattice, "", "  ")
		if err != nil {
			fmt.Println("error:", err)
		}
		fmt.Print(string(b))

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

	net, err := builder.Build("lattice")
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

	// fmt.Print("Press 'Enter' to continue...")
	// bufio.NewReader(os.Stdin).ReadBytes('\n')

	//Throughput Test
	// timer := time.NewTimer(time.Second)

	// done := false
	// go func() {
	// 	<-timer.C
	// 	done = true
	// }()

	// for !done {
	// 	sender := "tcp://10.150.0.2:3000"
	// 	receiver := "tcp://10.150.0.4:3000"
	// 	myMsg := "10"
	// 	myAmount, err := strconv.Atoi(myMsg)
	// 	if err != nil {
	// 		// handle error
	// 	}

	// 	//update lattice for sender
	// 	sendChain := net.Lattice[sender]
	// 	//generateCube(oldCube, typeOfTransaction, amount, signature, hash, timeSent, sender, receiver)
	// 	sendCube := generateCube(sendChain[len(sendChain)-1], "send", myAmount, sender, " ", time.Now(), sender, receiver)
	// 	sendChain = append(sendChain, sendCube)
	// 	net.Lattice[sender] = sendChain

	// 	s, err := json.Marshal(sendCube)
	// 	if err != nil {
	// 		fmt.Println("error:", err)
	// 	}

	// 	ctx := network.WithSignMessage(context.Background(), true)
	// 	net.Broadcast(ctx, &messages.ChatMessage{Message: string(s)})
	// }

	// Latency Test
	// for i := 0; i < 50; i++ {

	// 	timeSent := time.Now()

	// 	sender := " "
	// 	receiver := " "
	// 	if net.Address == "tcp://192.168.0.24:3000" {
	// 		sender = "tcp://192.168.0.24:3000"
	// 		receiver = "tcp://192.168.0.24:3001"
	// 	} else {
	// 		sender = "tcp://192.168.0.24:3001"
	// 		receiver = "tcp://192.168.0.24:3000"
	// 	}

	// 	myMsg := "10"
	// 	myAmount, err := strconv.Atoi(myMsg)
	// 	if err != nil {
	// 		// handle error
	// 	}

	// 	//update lattice for sender
	// 	sendChain := net.Lattice[sender]
	// 	sendCube := generateCube(sendChain[len(sendChain)-1], "send", myAmount, sender, " ", timeSent, sender, receiver)
	// 	sendChain = append(sendChain, sendCube)
	// 	net.Lattice[sender] = sendChain

	// 	s, err := json.Marshal(sendCube)
	// 	if err != nil {
	// 		fmt.Println("error:", err)
	// 	}

	// 	ctx := network.WithSignMessage(context.Background(), true)
	// 	net.Broadcast(ctx, &messages.ChatMessage{Message: string(s)})
	// }

	// Size Test
	// fmt.Println("Size of Lattice:  ", unsafe.Sizeof(net.Lattice[net.Address][0]))
	// }

	reader := bufio.NewReader(os.Stdin)

	for {
		input, _ := reader.ReadString('\n')

		// skip blank lines
		if len(strings.TrimSpace(input)) == 0 {
			continue
		}

		fullMsg := strings.Fields(input)

		sender := fullMsg[0]
		receiver := fullMsg[1]
		myMsg := fullMsg[2]
		myAmount, err := strconv.Atoi(myMsg)
		if err != nil {
			// handle error
		}

		//update lattice for sender
		sendChain := net.Lattice[sender]
		sendCube := generateCube(sendChain[len(sendChain)-1], "send", myAmount, sender, " ", time.Now(), sender, receiver)
		sendChain = append(sendChain, sendCube)
		net.Lattice[sender] = sendChain

		s, err := json.Marshal(sendCube)
		if err != nil {
			fmt.Println("error:", err)
		}

		ctx := network.WithSignMessage(context.Background(), true)
		net.Broadcast(ctx, &messages.ChatMessage{Message: string(s)})
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

// create a new cube
func generateCube(oldCube network.Cube, typeOfTransaction string, amount int, signature string, hash string, timeSent time.Time, sender string, receiver string) network.Cube {

	var newCube network.Cube

	newCube.Index = oldCube.Index + 1
	newCube.Previous = oldCube.Hash

	if typeOfTransaction == "send" {
		newCube.Balance = oldCube.Balance - amount

	} else {
		newCube.Balance = oldCube.Balance + amount
	}

	newCube.Type = typeOfTransaction
	newCube.Amount = amount

	if hash == " " {
		newCube.Hash = calculateHash(newCube)
	} else {
		newCube.Hash = hash
	}

	newCube.Signature = signature
	newCube.TimeSent = timeSent

	newCube.Sender = sender
	newCube.Receiver = receiver

	return newCube
}

// SHA256 hashing
func calculateHash(cube network.Cube) string {
	// record := strconv.Itoa(block.Index) + block.Timestamp +
	// 	strconv.Itoa(block.BPM) + block.PrevHash + block.Nonce
	record := strconv.Itoa(cube.Amount+cube.Balance+cube.Index) + cube.Type
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}
