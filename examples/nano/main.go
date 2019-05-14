package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	log2 "log"
	net2 "net"
	"os"
	"strconv"
	"strings"
	"time" //"unsafe"

	"github.com/perlin-network/myNoise/crypto/ed25519"
	"github.com/perlin-network/myNoise/examples/chat/messages"
	"github.com/perlin-network/myNoise/log"
	"github.com/perlin-network/myNoise/network"
	"github.com/perlin-network/myNoise/network/discovery"
	"github.com/perlin-network/myNoise/types/opcode"
)

type ChatPlugin struct{ *network.Plugin }

func (state *ChatPlugin) Receive(ctx *network.PluginContext) error {
	switch msg := ctx.Message().(type) {
	case *messages.ChatMessage:
		//log.Info().Msgf("<%s> %s", ctx.Client().ID.Address, "Received: "+msg.Message)

		myAmount, err := strconv.Atoi(msg.Message)
		if err != nil {
			// handle error
		}

		//update chain
		newCube := generateCube(ctx.Network().Chain[len(ctx.Network().Chain)-1], "receive", myAmount)
		ctx.Network().Chain = append(ctx.Network().Chain, newCube)

		//Latency Test
		fmt.Println("# of transactions: ", len(ctx.Network().Chain))

		timeSent, err := strconv.ParseInt(msg.Message, 10, 64)
		if err != nil {
			fmt.Println(err)
		}

		now := time.Now()
		timeNanos := now.UnixNano()

		nanos := timeNanos - timeSent
		fmt.Printf("Latency: %dns", nanos)
		fmt.Println()
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

	net, err := builder.Build("nano")
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

		// Throughput Test
		timer := time.NewTimer(time.Second)

		done := false
		go func() {
			<-timer.C
			done = true
		}()

		for !done {

			myRecipient := "tcp://10.150.0.7:3000"
			myMsg := "10"
			myAmount, err := strconv.Atoi(myMsg)
			if err != nil {
				// handle error
			}

			ctx := network.WithSignMessage(context.Background(), true)

			if client, err := net.Client(myRecipient); err == nil {
				client.Tell(ctx, &messages.ChatMessage{Message: myMsg})
				//log.Info().Msgf("<%s> %s", net.Address, "Sent: "+myMsg)

				//update chain
				newCube := generateCube(net.Chain[len(net.Chain)-1], "send", myAmount)
				net.Chain = append(net.Chain, newCube)

				//fmt.Printf("%+v\n", net.Chain)
			}
		}

		// Latency Test
		for i := 0; i < 400; i++ {
			now := time.Now()
			timeNanos := now.UnixNano()

			myRecipient := "tcp://192.168.0.16:3003"
			timeString := strconv.FormatInt(timeNanos, 10)
			myAmount := 10

			ctx := network.WithSignMessage(context.Background(), true)

			if client, err := net.Client(myRecipient); err == nil {
				//log.Info().Msgf("<%s> %s", net.Address, "Sent: "+timeString)

				//update chain
				newCube := generateCube(net.Chain[len(net.Chain)-1], "send", myAmount)
				net.Chain = append(net.Chain, newCube)

				//fmt.Printf("%+v\n", net.Chain)

				client.Tell(ctx, &messages.ChatMessage{Message: timeString})
			}
		}
	}

	// Size Test
	//fmt.Println("Size of Nano:  ", unsafe.Sizeof(net.Chain))

	reader := bufio.NewReader(os.Stdin)

	for {
		input, _ := reader.ReadString('\n')

		// skip blank lines
		if len(strings.TrimSpace(input)) == 0 {
			continue
		}

		ss := strings.Fields(input)

		myRecipient := ss[0]
		myMsg := ss[1]
		myAmount, err := strconv.Atoi(myMsg)
		if err != nil {
			// handle error
		}

		ctx := network.WithSignMessage(context.Background(), true)

		if client, err := net.Client(myRecipient); err == nil {
			client.Tell(ctx, &messages.ChatMessage{Message: myMsg})
			log.Info().Msgf("<%s> %s", net.Address, "Sent: "+myMsg)

			//update chain
			newCube := generateCube(net.Chain[len(net.Chain)-1], "send", myAmount)
			net.Chain = append(net.Chain, newCube)

			fmt.Printf("%+v\n", net.Chain)
		}
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
func generateCube(oldCube network.Cube, typeOfTransaction string, amount int) network.Cube {

	var newCube network.Cube

	newCube.Index = oldCube.Index + 1

	if typeOfTransaction == "send" {
		newCube.Balance = oldCube.Balance - amount
	} else {
		newCube.Balance = oldCube.Balance + amount
	}

	newCube.Type = typeOfTransaction
	newCube.Amount = amount

	return newCube
}
