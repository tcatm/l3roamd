# l3roamd

l3roamd is supposed to become a core part of future layer 3 mesh networks.
At first it will be built to work with [babeld](https://github.com/jech/babeld).

l3roamd will be doing quite a few things:

 - manage a lot of host routes
 - integrate tightly with the mac80211 layer for monitor the presence of clients
 - manage a distributed database in tandem with all l3roamd nodes within the mesh [DB]
 - manage distribution of prefixes across the mesh (for router advertisements) [RA]
 - proxy neighbour discovery across the mesh
 - monitor babeld for duplicate host routes that this node also announces
 
Ideally, I'd like to split this up into multiple daemons communicating using standardized protocols:
 
## [DB] Distributed Database
 
The database could become its own daemon. It's basically a key-value database that can answer a single question:

*Does anyone know a client with this $MAC and if so, what IPs did it use and who has served this client recently?*

This information does not need to be present on all nodes (though that's probably the naïve approach we'll take first).
It just needs to be reasonable certain that a node noticing a client previously unknown to it can figure out whether
that client has been known by some other node within the last, say, 15 minutes or so.
This timeout depends primarily on the lifecycle of host routes within l3roamd.

The most important outcome of querying the database is actually:
Notify any node that thinks it serves client to let go of it and instruct it to release all host routes.
Taking over those routes is a welcome side effect as it improves roaming.
In the worst case neighbour discovery will be able to re-establish these routes, though.

### Data stored about clients

 - MAC
 - a set of nodes that have served this client before
 - a set of IPs
 - (optional) a set of multicast groups

This dataset needs some timeouts and so on.

### Set of routeable client prefixes

A secondary usage of the database will probably be managing a set of prefixes used within the mesh.
There will be some set of prefixes clients may use.
This set may change at runtime depending on which prefixes may be used within the network.
l3roamd needs to track these.

## [RA] Router Advertisements

Any node should be able to announce a prefix (a /64) to be used by clients.
This must be announced both within l3roamd and as a default route with a source prefix (set to the announced prefix!)
through babeld.
A metric (e.g. uplink bandwidth, reliability, ...) should be included, too.
Nodes should announce a small subset of prefixes from nearby uplinks (actually, metric based) to clients via normal
router advertisements.
Lifetime of these prefixes should be managed such that clients always use the best uplink available.
This is where early loadbalancing can reasonably take place.
Clients are expected to cope with changing prefixes.
Clients are also expected to hold onto deprecated prefixes as long as active connections require it.
Routing for all, even deprecated, prefixes will be maintained as long as reasonably possible to avoid breaking a clients (TCP) connection.
Multiple default routes for prefixes may be common (think multi homed AS), in this case loadbalancing is delegated to babeld.
This means, that multiple nodes will announce the same set of prefixes with possibly different metrics.
l3roamd will manages the prefixes it announces to a client on a per-client basis, if possibly.
I.e. it will actively deprecate prefixes of clients it deems unreliably.
This is likely to happen during roaming longer distances when a completely different set of uplinks should be used.
As stated before, this will not break active connections.

## Managing clients

l3roamd will directly monitor a set of wireless interfaces for clients.
On the mac80211 layer it will monitor clients and act whenever a new client appears (query the database or create an entry)
or when a client disappears (it should use its own timeout instead relying on the mac80211 internal timeout).
In case of a disappearing client a node should remove all host routes for that client but
not yet forget about them completely (in case the client re-appears).
The routes presence in the routing table is controlled by the presence of the client (subject to some timeout).
The routes presence in the database is subject to the timeout of the IPs lifetime (as was announced by the RA).
Getting these mechanics right is crucial for sane roaming behaviour during bad network conditions.
In worst case two nodes may have to switch routes fast and repeatably due to a client having bad connectivity
to either node.
These nodes may not be connected directly.

## The host route lifecycle

Host routes need to have some kind of timeout.
This directly correlates with management traffic overhead.
It also affects the worst case amount of time a client will be unreachable in case of severe network conditions.

## IPv4?

Well, not really. This is IPv6 only.
We may, however, once everything works nicely, define a way for mapping IPv4 prefixes within IPv6 and rely on
some other translation mechanism (SIIT, NIIT, whatever) to carry the payload.
We may also extend the neighbour discovery proxy code to work with ARP.
Ideally, this will be a seperate daemon.

## Improvements welcome!

If you can improve this specifications (typos, better wording, restructering, ...) or even new important aspects, feel free to open
a pull request. Please prefix your commits with "README: $my message" and try to summarize the changes in the commit
message even if the commit message turns out to be longer than the change. Say, if you change a singel word, write a message like

    README: corrected singel to single
    
    This corrects a typo in the "Improvements welcome!" section.

This approach makes reviewing and reasoning about changes a lot easier.
