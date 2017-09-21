[counttable.bro](counttable.bro)
--------------------------------

This script provives the COUNTTABLE type for the Bro summary statistics
framework.  This type works similar to SUM, but bins values for each $str
provided in the observation. (SUM itself does not accept a string).

This makes it possible to count the aggregate sum for a small number of keys
per host like, for example, all TLS ciphers that were seen in use for hosts
in the local subnet.

This structure should not be used with a high number of different $str values,
especially in cluster setups. If used like this it can cause excessive resource
use.

Example
-------

The following example counts the number of times each HTTP status code was
encountered, counted by server address.

```bro
@load packages/bro-sumstats-counttable

event bro_init()
	{
	local r1 = SumStats::Reducer($stream="status.code", $apply=set(SumStats::COUNTTABLE));
	SumStats::create([$name="http-status-codes",
		$epoch=1hr, $reducers=set(r1),
		$epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
		{
			local r = result["status.code"];
			# abort if we have no results
			if ( ! r?$counttable )
				return;

			local counttable = r$counttable;
			print fmt("Host: %s", key$host);
			for ( i in counttable )
				print fmt("status code: %s, count: %d", i, counttable[i]);
		}]);
	}

event http_reply(c: connection, version: string, code: count, reason: string)
	{
	SumStats::observe("status.code", [$host=c$id$resp_h], [$str=cat(code), $num=1]);
	}
```

This will lead to output similar to:

```
Host: 8.12.217.126
status code: 200, count: 16
status code: 304, count: 6
Host: 68.71.208.110
status code: 200, count: 2
Host: 68.71.209.235
status code: 200, count: 18
status code: 304, count: 3
```
