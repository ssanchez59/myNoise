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
	"math"
	mrand "math/rand"
	net2 "net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time" //"unsafe"

	"github.com/perlin-network/myNoise/crypto/ed25519"
	"github.com/perlin-network/myNoise/examples/chat/messages"
	"github.com/perlin-network/myNoise/log"
	"github.com/perlin-network/myNoise/network"
	"github.com/perlin-network/myNoise/network/discovery"
	"github.com/perlin-network/myNoise/types/opcode"
)

type ChatPlugin struct{ *network.Plugin }

var mutex = &sync.Mutex{}

type tangle struct {
	Transactions []network.Transaction
	Links        []network.Link
	State        map[string]int
}

func (state *ChatPlugin) Receive(ctx *network.PluginContext) error {
	switch msg := ctx.Message().(type) {
	case *messages.ChatMessage:
		//log.Info().Msgf("<%s> %s", ctx.Client().ID.Address, msg.Message)
		t1 := tangle{
			Transactions: make([]network.Transaction, 0),
			Links:        make([]network.Link, 0),
			State:        make(map[string]int),
		}

		if err := json.Unmarshal([]byte(msg.Message), &t1); err != nil {
			log2.Fatal(err)
		}

		mutex.Lock()
		if len(t1.Transactions) > len(ctx.Network().Tangle.Transactions) &&
			len(t1.Links) > len(ctx.Network().Tangle.Links) {
			ctx.Network().Tangle.Transactions = t1.Transactions
			ctx.Network().Tangle.Links = t1.Links
			ctx.Network().Tangle.State = t1.State

			bytes, err := json.MarshalIndent(ctx.Network().Tangle, "", "  ")
			if err != nil {

				log2.Fatal(err)
			}
			// Green console color: 	\x1b[32m
			// Reset console color: 	\x1b[0m
			fmt.Printf("\x1b[32m%s\x1b[0m> ", string(bytes))
			// fmt.Println("# Transactions: ", len(ctx.Network().Tangle.Transactions))

		}
		mutex.Unlock()

		//Latency test
		// lastTransaction := ctx.Network().Tangle.Transactions[len(ctx.Network().Tangle.Transactions)-1]
		// elapsed := time.Since(lastTransaction.TimeSent)
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

	net, err := builder.Build("tangle")
	if err != nil {
		log.Fatal().Err(err)
		return
	}

	go net.Listen()

	if len(peers) > 0 {
		net.Bootstrap(peers...)
	}

	// Tests
	// if net.Address == "tcp://192.168.0.18:3000" {

	// 	fmt.Print("Press 'Enter' to continue...")
	// 	bufio.NewReader(os.Stdin).ReadBytes('\n')

	// Throughput Tests
	// timer := time.NewTimer(time.Second)

	// done := false
	// go func() {
	// 	<-timer.C
	// 	done = true
	// }()

	// for !done {

	// 	amountInt := 10

	// 	from := "Bob"
	// 	to := "Alice"

	// 	net.Tangle.State[from] = net.Tangle.State[from] - amountInt
	// 	net.Tangle.State[to] = net.Tangle.State[to] + amountInt

	// 	newTransaction := generateTransaction(net.Tangle.Transactions[len(net.Tangle.Transactions)-1], "send 10 from Bob to Alice", net.Address, time.Time{})

	// 	//START: New way of forming Links
	// 	candidates := []int{}
	// 	for _, c := range net.Tangle.Transactions {
	// 		if newTransaction.TimeInt-net.Tangle.H > c.TimeInt {
	// 			candidates = append(candidates, c.Index)
	// 		}
	// 	}

	// 	candidateLinks := []network.Link{}
	// 	for _, l := range net.Tangle.Links {
	// 		if newTransaction.TimeInt-net.Tangle.H > net.Tangle.Transactions[l.Source].TimeInt {
	// 			candidateLinks = append(candidateLinks, l)
	// 		}
	// 	}

	// 	tips := getTips(net.Tangle.TipSelection, candidates, candidateLinks, net.Tangle)

	// 	mutex.Lock()
	// 	if len(tips) > 0 {
	// 		newTransaction.HashApp1 = calculateHash(net.Tangle.Transactions[tips[0]])
	// 		newLink := generateLink(net.Tangle.Transactions[tips[0]], newTransaction)
	// 		net.Tangle.Links = append(net.Tangle.Links, newLink)
	// 		if len(tips) > 1 && tips[0] != tips[1] {
	// 			newTransaction.HashApp2 = calculateHash(net.Tangle.Transactions[tips[1]])
	// 			newLink := generateLink(net.Tangle.Transactions[tips[1]], newTransaction)
	// 			net.Tangle.Links = append(net.Tangle.Links, newLink)
	// 		}
	// 	}
	// 	net.Tangle.Transactions = append(net.Tangle.Transactions, newTransaction)
	// 	mutex.Unlock()

	// 	bytes, err := json.Marshal(net.Tangle)
	// 	if err != nil {
	// 		log2.Println(err)
	// 	}

	// 	ctx := network.WithSignMessage(context.Background(), true)
	// 	net.Broadcast(ctx, &messages.ChatMessage{Message: string(bytes)})
	// }

	// 	// Latency Test
	// 	for i := 0; i < 4; i++ {
	// 		timeSent := time.Now()

	// 		amountInt := 10

	// 		from := "Alice"
	// 		to := "Bob"

	// 		net.Tangle.State[from] = net.Tangle.State[from] - amountInt
	// 		net.Tangle.State[to] = net.Tangle.State[to] + amountInt

	// 		newTransaction := generateTransaction(net.Tangle.Transactions[len(net.Tangle.Transactions)-1], "send 10 from Bob to Alice", net.Address, timeSent)

	// 		//START: New way of forming Links
	// 		candidates := []int{}
	// 		for _, c := range net.Tangle.Transactions {
	// 			if newTransaction.TimeInt-net.Tangle.H > c.TimeInt {
	// 				candidates = append(candidates, c.Index)
	// 			}
	// 		}

	// 		candidateLinks := []network.Link{}
	// 		for _, l := range net.Tangle.Links {
	// 			if newTransaction.TimeInt-net.Tangle.H > net.Tangle.Transactions[l.Source].TimeInt {
	// 				candidateLinks = append(candidateLinks, l)
	// 			}
	// 		}

	// 		tips := getTips(net.Tangle.TipSelection, candidates, candidateLinks, net.Tangle)

	// 		mutex.Lock()
	// 		if len(tips) > 0 {
	// 			newTransaction.HashApp1 = calculateHash(net.Tangle.Transactions[tips[0]])
	// 			newLink := generateLink(net.Tangle.Transactions[tips[0]], newTransaction)
	// 			net.Tangle.Links = append(net.Tangle.Links, newLink)
	// 			if len(tips) > 1 && tips[0] != tips[1] {
	// 				newTransaction.HashApp2 = calculateHash(net.Tangle.Transactions[tips[1]])
	// 				newLink := generateLink(net.Tangle.Transactions[tips[1]], newTransaction)
	// 				net.Tangle.Links = append(net.Tangle.Links, newLink)
	// 			}
	// 		}
	// 		net.Tangle.Transactions = append(net.Tangle.Transactions, newTransaction)
	// 		mutex.Unlock()

	// 		bytes, err := json.Marshal(net.Tangle)
	// 		if err != nil {
	// 			log2.Println(err)
	// 		}

	// 		ctx := network.WithSignMessage(context.Background(), true)
	// 		net.Broadcast(ctx, &messages.ChatMessage{Message: string(bytes)})
	// 	}
	// }

	// Size Test
	// fmt.Println("Size of Tangle - Transaction:  ", unsafe.Sizeof(net.Tangle.Transactions[0]))

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

		net.Tangle.State[from] = net.Tangle.State[from] - amountInt
		net.Tangle.State[to] = net.Tangle.State[to] + amountInt

		newTransaction := generateTransaction(net.Tangle.Transactions[len(net.Tangle.Transactions)-1], input, net.Address, time.Now())

		//START: New way of forming Links

		candidates := []int{}
		for _, c := range net.Tangle.Transactions {
			if newTransaction.TimeInt-net.Tangle.H > c.TimeInt {
				candidates = append(candidates, c.Index)
			}
		}

		candidateLinks := []network.Link{}
		for _, l := range net.Tangle.Links {
			if newTransaction.TimeInt-net.Tangle.H > net.Tangle.Transactions[l.Source].TimeInt {
				candidateLinks = append(candidateLinks, l)
			}
		}

		tips := getTips(net.Tangle.TipSelection, candidates, candidateLinks, net.Tangle)

		mutex.Lock()
		if len(tips) > 0 {
			newTransaction.HashApp1 = calculateHash(net.Tangle.Transactions[tips[0]])
			newLink := generateLink(net.Tangle.Transactions[tips[0]], newTransaction)
			net.Tangle.Links = append(net.Tangle.Links, newLink)
			if len(tips) > 1 && tips[0] != tips[1] {
				newTransaction.HashApp2 = calculateHash(net.Tangle.Transactions[tips[1]])
				newLink := generateLink(net.Tangle.Transactions[tips[1]], newTransaction)
				net.Tangle.Links = append(net.Tangle.Links, newLink)
			}
		}
		net.Tangle.Transactions = append(net.Tangle.Transactions, newTransaction)
		mutex.Unlock()

		bytes, err := json.Marshal(net.Tangle)
		if err != nil {
			log2.Println(err)
		}

		ctx := network.WithSignMessage(context.Background(), true)
		net.Broadcast(ctx, &messages.ChatMessage{Message: string(bytes)})

		// fmt.Println("Size of Tangle - Link:  ", unsafe.Sizeof(net.Tangle.Links[0]))
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

// create a new Transaction using previous Transactions index
func generateTransaction(lastTransaction network.Transaction, Operation string, address string, timeSent time.Time) network.Transaction {

	var newTransaction network.Transaction

	newTransaction.Index = lastTransaction.Index + 1
	newTransaction.Operation = Operation
	newTransaction.IotaTime = 0

	now := time.Now()
	newTransaction.TimeInt = now.UnixNano() / 1000000
	newTransaction.TimeString = time.Unix(0, now.UnixNano()).String()
	newTransaction.Weight = 1
	newTransaction.Signature = address
	newTransaction.Hash = calculateHash(newTransaction)

	newTransaction.TimeSent = timeSent

	return newTransaction
}

// create a new Link from a source transaction to a target transaction
func generateLink(target network.Transaction, source network.Transaction) network.Link {

	var newLink network.Link

	newLink.Target = target.Index
	newLink.Source = source.Index

	return newLink

}

func getTips(algorithm string, candidates []int, candidateLinks []network.Link, Tangle network.DAG) []int {

	if algorithm == "uniformRandom" {

		paso1 := []int{}
		for _, t := range candidates {
			if isTip(Tangle.Transactions[t], Tangle) {
				paso1 = append(paso1, t)
			}
		}

		if len(candidateLinks) == 0 {
			return []int{0}
		}

		tips := []int{}
		for _, t := range paso1 {
			for _, l := range candidateLinks {
				if l.Source == t {
					tips = append(tips, t)
				}
			}
		}

		if len(tips) == 0 {
			return []int{}
		}
		return []int{choose(tips), choose(tips)}
	}
	if algorithm == "unWeightedMCMC" {

		if len(Tangle.Transactions) == 0 {
			return []int{}
		}

		start := Tangle.Transactions[0]

		return []int{randomWalk(start, Tangle).Index, randomWalk(start, Tangle).Index}

	}
	if algorithm == "weightedMCMC" {

		if len(Tangle.Transactions) == 0 {
			return []int{}
		}

		start := Tangle.Transactions[0]

		calculateWeights(Tangle)

		return []int{weightedRandomWalk(start, Tangle).Index, weightedRandomWalk(start, Tangle).Index}

	}
	return []int{}

}

// SHA256 hashing
func calculateHash(transaction network.Transaction) string {
	// record := strconv.Itoa(block.Index) + block.Timestamp +
	// 	strconv.Itoa(block.BPM) + block.PrevHash + block.Nonce
	record := strconv.Itoa(transaction.Index) + transaction.TimeString
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

func choose(array []int) int {
	source := mrand.NewSource(time.Now().UnixNano())
	r := mrand.New(source)
	index := r.Intn(len(array))

	return array[index]
}

func isTip(transaction network.Transaction, Tangle network.DAG) bool {

	cuenta := 0

	for _, link := range Tangle.Links {
		if link.Target == transaction.Index {
			cuenta++
		}
	}

	if cuenta < 2 {
		return true
	}
	return false
}

func randomWalk(start network.Transaction, Tangle network.DAG) network.Transaction {
	particle := start

	if !isTip(particle, Tangle) {
		approvers := getApprovers(particle, Tangle)
		if len(approvers) != 0 {
			particle = randomWalk(Tangle.Transactions[choose(approvers)], Tangle)
		}
	}

	return particle
}

func weightedRandomWalk(start network.Transaction, Tangle network.DAG) network.Transaction {
	particle := start

	if !isTip(particle, Tangle) {

		approvers := getApprovers(particle, Tangle)
		if len(approvers) != 0 {

			cumWeights := []int{}
			for _, approver := range approvers {
				cumWeights = append(cumWeights, Tangle.Transactions[approver].CumWeight)
			}

			// normalize so maximum cumWeight is 0
			_, maxCumWeight := minMax(cumWeights)
			normalizedWeights := []int{}
			for i := 0; i < len(cumWeights); i++ {
				normalizedWeights = append(normalizedWeights, cumWeights[i]-maxCumWeight)
			}

			weights := []float64{}
			for i := 0; i < len(normalizedWeights); i++ {
				weights = append(weights, math.Exp(float64(normalizedWeights[i])*float64(Tangle.Alpha)))
			}
			myInt := weightedChoose(approvers, weights)
			particle = weightedRandomWalk(Tangle.Transactions[myInt], Tangle)
		}
	}

	return particle
}

func weightedChoose(approvers []int, weights []float64) int {

	sum := float64(0)
	for i := 0; i < len(weights); i++ {
		sum = sum + weights[i]
	}
	rand := randomFloat() * sum

	cumSum := weights[0]
	for i := 1; i < len(approvers); i++ {
		if rand < cumSum {
			return approvers[i-1]
		}
		cumSum = cumSum + weights[i]
	}
	return approvers[len(approvers)-1]

}

func getApprovers(transanction network.Transaction, Tangle network.DAG) []int {
	approvers := []int{}

	for _, link := range Tangle.Links {
		if link.Target == transanction.Index {
			approvers = append(approvers, link.Source)
		}
	}

	return approvers
}

func calculateWeights(Tangle network.DAG) {
	sorted := topologicalSort(Tangle)

	//Initialize an empty slice for each node
	l := len(Tangle.Transactions)
	ancestorSlices := make([][]int, l)

	childrenLists := getChildrenLists(Tangle)

	for _, node := range sorted {
		for _, child := range childrenLists[node] {
			ancestorSlices[child] = append(ancestorSlices[child], ancestorSlices[node]...)
			ancestorSlices[child] = append(ancestorSlices[child], node)
		}
		ancestorSlices[node] = unique(ancestorSlices[node])
		Tangle.Transactions[node].CumWeight = len(ancestorSlices[node]) + 1
	}
}

func minMax(array []int) (int, int) {
	var max = array[0]
	var min = array[0]
	for _, value := range array {
		if max < value {
			max = value
		}
		if min > value {
			min = value
		}
	}
	return min, max
}

func randomFloat() float64 {
	source := mrand.NewSource(time.Now().UnixNano())
	r := mrand.New(source)

	return r.Float64()
}

func topologicalSort(Tangle network.DAG) []int {
	childrenLists := getChildrenLists(Tangle)
	unvisited := Tangle.Transactions
	result := []int{}

	for len(unvisited) > 0 {
		t := unvisited[0]
		result, unvisited = visit(t, unvisited, childrenLists, result, Tangle)
	}

	// Reverse slice
	for i := len(result)/2 - 1; i >= 0; i-- {
		opp := len(result) - 1 - i
		result[i], result[opp] = result[opp], result[i]
	}

	// Add 0
	return result
}

func getChildrenLists(Tangle network.DAG) [][]int {

	l := len(Tangle.Transactions)

	childrenLists := make([][]int, l)

	for _, link := range Tangle.Links {
		childrenLists[link.Source] = append(childrenLists[link.Source], link.Target)
	}

	return childrenLists
}

func unique(intSlice []int) []int {
	keys := make(map[int]bool)
	list := []int{}
	for _, entry := range intSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func visit(transaction network.Transaction, unvisited []network.Transaction, childrenLists [][]int, result []int, Tangle network.DAG) ([]int, []network.Transaction) {

	esta := false
	for _, t := range unvisited {
		if transaction.Index == t.Index {
			esta = true
		}
	}
	if !esta {
		return nil, nil
	}

	for _, child := range childrenLists[transaction.Index] {
		visit(Tangle.Transactions[child], unvisited, childrenLists, result, Tangle)
	}

	result = append(result, unvisited[0].Index)
	newUnvisited := unvisited[1:]

	return result, newUnvisited
}
