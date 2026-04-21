// true-positive-03: AWS_SECRET_ACCESS_KEY written to the CI log via
// console.log. Log exposure — a high-severity variant that persists in
// workflow run history.

function debugBuild() {
  const awsKey = process.env.AWS_SECRET_ACCESS_KEY;
  console.log("Build context:", awsKey);
}

debugBuild();
