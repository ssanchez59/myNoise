package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex" //"encoding/json"
	"flag"
	"fmt"
	log2 "log"
	net2 "net"
	"os"
	"strconv"
	"strings"
	"sync" // "unsafe"
	"time"

	"github.com/perlin-network/myNoise/crypto/ed25519"
	"github.com/perlin-network/myNoise/examples/chat/messages"
	"github.com/perlin-network/myNoise/log"
	"github.com/perlin-network/myNoise/network"
	"github.com/perlin-network/myNoise/network/discovery"
	"github.com/perlin-network/myNoise/types/opcode"
)

type ChatPlugin struct{ *network.Plugin }

var mutex = &sync.Mutex{}

func (state *ChatPlugin) Receive(ctx *network.PluginContext) error {
	switch msg := ctx.Message().(type) {
	case *messages.ChatMessage:
		//log.Info().Msgf("<%s> %s", ctx.Client().ID.Address, "Received: "+msg.Message)

		fullMsg := strings.Fields(msg.Message)

		// Broadcast(
		// 	0 sender
		// 	1 receiver
		// 	2 myMsg
		//  3 Hash of transaction
		//  4 Hash of source transaction
		// 	5 timeSent
		// )

		owner := fullMsg[0]
		receiver := fullMsg[1]
		myMsg := fullMsg[2]
		myAmount, err := strconv.Atoi(myMsg)
		if err != nil {
			// handle error
		}
		transactionHash := fullMsg[3]
		sourceHash := fullMsg[4]
		timeSentString := fullMsg[5]

		//update lattice for owner
		mutex.Lock()
		ownerChain := ctx.Network().Lattice[owner]

		newCube := network.Cube{}
		// generateCube(oldCube, type, amount, signature, hash of transaction, sender, receiver)
		if receiver != "ignore" {
			newCube = generateCube(ownerChain[len(ownerChain)-1], "send", myAmount, owner, transactionHash, owner, receiver)
		} else {
			newCube = generateCube(ownerChain[len(ownerChain)-1], "receive", myAmount, owner, transactionHash, owner, receiver)
			newCube.Source = sourceHash
		}

		ownerChain = append(ownerChain, newCube)
		ctx.Network().Lattice[owner] = ownerChain
		mutex.Unlock()

		// b, err := json.MarshalIndent(ctx.Network().Lattice, "", "  ")
		// if err != nil {
		// 	fmt.Println("error:", err)
		// }
		// fmt.Print(string(b))

		//update lattice for receiver
		if ctx.Network().Address == receiver {
			receiveChain := ctx.Network().Lattice[receiver]
			// generateCube(oldCube, type, amount, signature, hash of transaction, sender, receiver)
			newCube = generateCube(receiveChain[len(receiveChain)-1], "receive", myAmount, receiver, " ", " ", " ")
			newCube.Source = sourceHash
			receiveChain = append(receiveChain, newCube)
			ctx.Network().Lattice[receiver] = receiveChain

			ctx2 := network.WithSignMessage(context.Background(), true)

			// Broadcast(
			// 	0 sender
			// 	1 receiver
			// 	2 myMsg
			// 	3 Hash of transaction
			//  4 Hash of source transaction
			// 	5 timeSent
			// )

			ctx.Network().Broadcast(ctx2, &messages.ChatMessage{
				Message: receiver + " " +
					"ignore" + " " +
					fullMsg[2] + " " +
					receiveChain[len(receiveChain)-1].Hash + " " +
					receiveChain[len(receiveChain)-1].Source + " " +
					timeSentString})
		}

		//Latency Test para creacion de (R)
		if receiver == "ignore" {
			
			fmt.Println("# of transactions: ", len(ctx.Network().Lattice[owner]))
			timeSent, err := strconv.ParseInt(timeSentString, 10, 64)
			if err != nil {
				fmt.Println(err)
			}

			now := time.Now()
			timeNanos := now.UnixNano()

			nanos := timeNanos - timeSent
			fmt.Printf("Latency: %dns", nanos)
			fmt.Println()
		}
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
	if net.Address == "tcp://10.150.0.2:3000" {

		fmt.Print("Press 'Enter' to continue...")
		bufio.NewReader(os.Stdin).ReadBytes('\n')

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
		// 	newCube := generateCube(sendChain[len(sendChain)-1], "send", myAmount, sender, " ", sender, receiver)
		// 	sendChain = append(sendChain, newCube)
		// 	net.Lattice[sender] = sendChain

		// 	ctx := network.WithSignMessage(context.Background(), true)

		// 	net.Broadcast(ctx, &messages.ChatMessage{
		// 		Message: sender + " " +
		// 			receiver + " " +
		// 			myMsg + " " +
		// 			sendChain[len(sendChain)-1].Hash + " " +
		// 			sendChain[len(sendChain)-1].Hash + " " +
		// 			"1"})
		// }

		// Latency Test
		for i := 0; i < 800; i++ {
			now := time.Now()
			timeNanos := now.UnixNano()
			timeString := strconv.FormatInt(timeNanos, 10)

			sender := "tcp://10.150.0.2:3000"
			receiver := "tcp://10.150.0.4:3000"
			myMsg := "10"
			myAmount, err := strconv.Atoi(myMsg)
			if err != nil {
				// handle error
			}

			//update lattice for sender
			sendChain := net.Lattice[sender]
			newCube := generateCube(sendChain[len(sendChain)-1], "send", myAmount, sender, " ", sender, receiver)
			sendChain = append(sendChain, newCube)
			net.Lattice[sender] = sendChain

			ctx := network.WithSignMessage(context.Background(), true)
			net.Broadcast(ctx, &messages.ChatMessage{
				Message:
				sender + " " +
				receiver + " " +
				myMsg + " " +
				sendChain[len(sendChain)-1].Hash + " " +
				sendChain[len(sendChain)-1].Hash + " " +
				timeString})
		}
	}

	// //Size Test
	// fmt.Println("Size of Lattice:  ", unsafe.Sizeof(net.Lattice))
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
		// generateCube(oldCube, type, amount, signature, hash, sender, receiver)
		newCube := generateCube(sendChain[len(sendChain)-1], "send", myAmount, sender, " ", sender, receiver)
		sendChain = append(sendChain, newCube)
		net.Lattice[sender] = sendChain

		ctx := network.WithSignMessage(context.Background(), true)

		// Broadcast(
		// 	sender
		// 	receiver
		// 	myMsg
		// 	Hash of send transaction
		//  Hash of source transaction
		// 	timeSent
		// )
		net.Broadcast(ctx, &messages.ChatMessage{
			Message: sender + " " +
				receiver + " " +
				myMsg + " " +
				sendChain[len(sendChain)-1].Hash + " " +
				sendChain[len(sendChain)-1].Hash + " " +
				"1"})

		// b, err := json.MarshalIndent(net.Lattice, "", "  ")
		// if err != nil {
		// 	fmt.Println("error:", err)
		// }
		// fmt.Print(string(b))
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
func generateCube(oldCube network.Cube, typeOfTransaction string, amount int, signature string, hash string, sender string, receiver string) network.Cube {

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
	newCube.Sender = sender
	newCube.Receiver = receiver

	return newCube
}

// SHA256 hashing
func calculateHash(cube network.Cube) string {
	// record := strconv.Itoa(block.Index) + block.Timestamp +
	// 	strconv.Itoa(block.BPM) + block.PrevHash + block.Nonce
	record := strconv.Itoa(cube.Amount + cube.Balance + cube.Index)
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}
