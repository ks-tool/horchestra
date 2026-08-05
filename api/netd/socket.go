package netd

// SocketPath is where the helper listens.
//
// Under a ROOT-owned directory on purpose: whoever owns the rendezvous point owns who may squat
// it, and a privileged process that dialed into a path an unprivileged user controls would be
// taking its orders from whoever won the race to create it. The agent, holding no privilege, is
// the one that connects — which is also the architecture's own rule: the agent opens no listening
// socket.
const SocketPath = "/run/horchestra/netd.sock"
