export async function runAttackChecks(config) {
  return [
    {
      attackId: "stage10-backup-verify",
      expected: "blocked",
      observed: "blocked"
    }
  ];
}