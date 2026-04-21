// true-negative-02: fs.unlink on a build artifact path — no audit
// marker. Must NOT fire.

import * as fs from "fs";

function cleanBuild() {
  fs.unlinkSync("./dist/bundle.js");
  fs.unlinkSync("./dist/bundle.js.map");
}

cleanBuild();
