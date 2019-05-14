package network

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"strconv"
	"sync"
	"time"

	"github.com/perlin-network/myNoise/crypto"
	"github.com/perlin-network/myNoise/crypto/blake2b"
	"github.com/perlin-network/myNoise/crypto/ed25519"
	"github.com/perlin-network/myNoise/network/transport"
	"github.com/perlin-network/myNoise/peer"
	"github.com/pkg/errors"
)

const (
	defaultAddress = "tcp://localhost:8588"
)

var (
	// ErrStrDuplicatePlugin returns if the plugin has already been registered
	// with the builder
	ErrStrDuplicatePlugin = "builder: plugin %s is already registered"
	// ErrStrNoAddress returns if no address was given to the builder
	ErrStrNoAddress = "builder: network requires public server IP for peers to connect to"
	// ErrStrNoKeyPair returns if no keypair was given to the builder
	ErrStrNoKeyPair = "builder: cryptography keys not provided to Network; cannot create node ID"
)

// Builder is a Address->processors struct
type Builder struct {
	opts options

	keys    *crypto.KeyPair
	address string

	plugins     *PluginList
	pluginCount int

	transports *sync.Map
}

var defaultBuilderOptions = options{
	connectionTimeout: defaultConnectionTimeout,
	signaturePolicy:   ed25519.New(),
	hashPolicy:        blake2b.New(),
	recvWindowSize:    defaultReceiveWindowSize,
	sendWindowSize:    defaultSendWindowSize,
	writeBufferSize:   defaultWriteBufferSize,
	writeFlushLatency: defaultWriteFlushLatency,
	writeTimeout:      defaultWriteTimeout,
}

// A BuilderOption sets options such as connection timeout and cryptographic // policies for the network
type BuilderOption func(*options)

// ConnectionTimeout returns a NetworkOption that sets the timeout for
// establishing new connections (default: 60 seconds).
func ConnectionTimeout(d time.Duration) BuilderOption {
	return func(o *options) {
		o.connectionTimeout = d
	}
}

// SignaturePolicy returns a BuilderOption that sets the signature policy
// for the network (default: ed25519).
func SignaturePolicy(policy crypto.SignaturePolicy) BuilderOption {
	return func(o *options) {
		o.signaturePolicy = policy
	}
}

// HashPolicy returns a BuilderOption that sets the hash policy for the network
// (default: blake2b).
func HashPolicy(policy crypto.HashPolicy) BuilderOption {
	return func(o *options) {
		o.hashPolicy = policy
	}
}

// RecvWindowSize returns a BuilderOption that sets the receive buffer window
// size (default: 4096).
func RecvWindowSize(recvWindowSize int) BuilderOption {
	return func(o *options) {
		o.recvWindowSize = recvWindowSize
	}
}

// SendWindowSize returns a BuilderOption that sets the send buffer window
// size (default: 4096).
func SendWindowSize(sendWindowSize int) BuilderOption {
	return func(o *options) {
		o.sendWindowSize = sendWindowSize
	}
}

// WriteBufferSize returns a BuilderOption that sets the write buffer size
// (default: 4096 bytes).
func WriteBufferSize(byteSize int) BuilderOption {
	return func(o *options) {
		o.writeBufferSize = byteSize
	}
}

// WriteFlushLatency returns a BuilderOption that sets the write flush interval
// (default: 50ms).
func WriteFlushLatency(d time.Duration) BuilderOption {
	return func(o *options) {
		o.writeFlushLatency = d
	}
}

// WriteTimeout returns a BuilderOption that sets the write timeout
// (default: 4096).
func WriteTimeout(d time.Duration) BuilderOption {
	return func(o *options) {
		o.writeTimeout = d
	}
}

// NewBuilder returns a new builder with default options.
func NewBuilder() *Builder {
	builder := &Builder{
		opts:       defaultBuilderOptions,
		address:    defaultAddress,
		keys:       ed25519.RandomKeyPair(),
		transports: new(sync.Map),
	}

	// Register default transport layers.
	builder.RegisterTransportLayer("tcp", transport.NewTCP())
	builder.RegisterTransportLayer("kcp", transport.NewKCP())

	return builder
}

// NewBuilderWithOptions returns a new builder with specified options.
func NewBuilderWithOptions(opt ...BuilderOption) *Builder {
	builder := NewBuilder()

	for _, o := range opt {
		o(&builder.opts)
	}

	return builder
}

// SetKeys pair created from crypto.KeyPair.
func (builder *Builder) SetKeys(pair *crypto.KeyPair) {
	builder.keys = pair
}

// SetAddress sets the host address for the network.
func (builder *Builder) SetAddress(address string) {
	builder.address = address
}

// AddPluginWithPriority registers a new plugin onto the network with a set priority.
func (builder *Builder) AddPluginWithPriority(priority int, plugin PluginInterface) error {
	// Initialize plugin list if not exist.
	if builder.plugins == nil {
		builder.plugins = NewPluginList()
	}

	if !builder.plugins.Put(priority, plugin) {
		return errors.Errorf(ErrStrDuplicatePlugin, reflect.TypeOf(plugin).String())
	}

	return nil
}

// AddPlugin register a new plugin onto the network.
func (builder *Builder) AddPlugin(plugin PluginInterface) error {
	err := builder.AddPluginWithPriority(builder.pluginCount, plugin)
	if err == nil {
		builder.pluginCount++
	}
	return err
}

// RegisterTransportLayer registers a transport layer to the network keyed by its name.
//
// Example: builder.RegisterTransportLayer("kcp", transport.NewKCP())
func (builder *Builder) RegisterTransportLayer(name string, layer transport.Layer) {
	builder.transports.Store(name, layer)
}

// ClearTransportLayers removes all registered transport layers from the builder.
func (builder *Builder) ClearTransportLayers() {
	builder.transports = new(sync.Map)
}

// Build verifies all parameters of the network and returns either an error due to
// misconfiguration, or a *Network.
func (builder *Builder) Build(structure string) (*Network, error) {
	if builder.keys == nil {
		return nil, errors.New(ErrStrNoKeyPair)
	}

	if len(builder.address) == 0 {
		return nil, errors.New(ErrStrNoAddress)
	}

	// Initialize plugin list if not exist.
	if builder.plugins == nil {
		builder.plugins = NewPluginList()
	} else {
		builder.plugins.SortByPriority()
	}

	unifiedAddress, err := ToUnifiedAddress(builder.address)
	if err != nil {
		return nil, err
	}

	id := peer.CreateID(unifiedAddress, builder.keys.PublicKey)

	net := &Network{
		opts:    builder.opts,
		ID:      id,
		keys:    builder.keys,
		Address: unifiedAddress,

		plugins:    builder.plugins,
		transports: builder.transports,

		peers:       new(sync.Map),
		connections: new(sync.Map),

		listeningCh: make(chan struct{}),
		kill:        make(chan struct{}),
	}

	//Decide which structure to build
	switch structure {

	case "chat":
		fmt.Println("STRUCTURE: CHAT")

	case "blockchain":
		fmt.Println("STRUCTURE: BLOCKCHAIN")

		state := make(map[string]int)
		net.Blockchain.State = state

		genesisBlock := Block{}
		now := time.Now()
		genesisBlock = Block{0, time.Unix(0, now.UnixNano()).String(), "", calculateHash(genesisBlock), "", "", time.Now()}

		net.Blockchain.Blocks = []Block{genesisBlock}

	case "tangle":
		fmt.Println("STRUCTURE: TANGLE")

		net.Tangle.Lambda = 1.5
		net.Tangle.Alpha = 0.5
		net.Tangle.H = 1
		net.Tangle.TipSelection = "weightedMCMC"

		//Initial State
		state := make(map[string]int)
		net.Tangle.State = state

		genesisTransaction := Transaction{}
		now := time.Now()
		genesisTransaction = Transaction{0, "genesis", 0, now.UnixNano() / 1000000, time.Unix(0, now.UnixNano()).String(), 1, 0, "", "", "", "", time.Now()}
		genesisTransaction.Hash = calculateHashTransaction(genesisTransaction)

		net.Tangle.Transactions = []Transaction{genesisTransaction}

	case "nano":
		fmt.Println("STRUCTURE: NANO")
		genesisCube := Cube{}
		genesisCube = Cube{0, 0, "open", 0, " ", " ", " ", " ", time.Now(), " ", " "}
		net.Chain = []Cube{genesisCube}

	case "lattice":
		fmt.Println("STRUCTURE: BLOCK-LATTICE")
		genesisCube := Cube{}
		genesisCube = Cube{0, 0, "open", 0, " ", " ", " ", " ", time.Now(), " ", " "}
		chain := []Cube{genesisCube}
		net.Lattice = map[string][]Cube{
			"tcp://192.168.0.18:3000": chain,
			"tcp://192.168.0.18:3001": chain,
			// "tcp://10.150.0.2:3000": chain,
			// "tcp://10.150.0.4:3000": chain,
			// "tcp://10.150.0.6:3000": chain,
			// "tcp://10.150.0.7:3000":  chain,
			// "tcp://10.150.0.8:3000":  chain,
			// "tcp://10.150.0.9:3000":  chain,
			// "tcp://10.150.0.11:3000": chain,
			// "tcp://10.150.0.10:3000": chain,
		}
	}

	net.Init()

	return net, nil
}

// SHA256 hashing
func calculateHash(block Block) string {
	// record := strconv.Itoa(block.Index) + block.Timestamp +
	// 	strconv.Itoa(block.BPM) + block.PrevHash + block.Nonce
	record := strconv.Itoa(block.Index) + block.Timestamp + block.PrevHash + block.Signature
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

func calculateHashTransaction(transaction Transaction) string {
	// record := strconv.Itoa(block.Index) + block.Timestamp +
	// 	strconv.Itoa(block.BPM) + block.PrevHash + block.Nonce
	record := strconv.Itoa(transaction.Index) + transaction.TimeString
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}
