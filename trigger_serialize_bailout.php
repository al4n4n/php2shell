<?php
// Trigger OOM specifically DURING serialize() to leave BG(serialize) dirty.
//
// Strategy: build a modest-sized data structure that fits in memory,
// but whose serialized representation is much larger (string expansion).
// The OOM hits during the serialize() call itself.

error_reporting(E_ALL);

// Build array that fits in ~8MB but serializes to ~20MB+
// Each element is a short key mapping to a moderate string.
// The array itself takes ~6MB, but serialize() must allocate
// a contiguous output buffer that grows during serialization.
$arr = [];
for ($i = 0; $i < 5000; $i++) {
    // ~1KB per value, but serialize adds framing per entry
    $arr["k$i"] = str_repeat(chr(65 + ($i % 26)), 1024);
}
// At this point, ~5-6MB used for the array.
// serialize() will try to build a ~6MB+ output string on top of that,
// pushing past the 16MB limit mid-serialization.

echo "pid: " . getmypid() . "\n";
echo "array built, starting serialize...\n";
flush();

$result = serialize($arr);

echo "serialize completed - memory was sufficient (need lower limit or bigger data)\n";
