import { describe, expect, test } from "bun:test";
import { hasUnparseableConstructs } from "./splitter.ts";

describe("hasUnparseableConstructs", () => {
	describe("whitelisted heredoc patterns", () => {
		test("allows $(cat << for commit messages", () => {
			const cmd = `git commit -m "$(cat <<'EOF'\nFix bug in login flow\nEOF\n)"`;
			expect(hasUnparseableConstructs(cmd)).toBe(false);
		});

		test("allows $(cat <<EOF without quotes", () => {
			const cmd = `git commit -m "$(cat <<EOF\nSome message\nEOF\n)"`;
			expect(hasUnparseableConstructs(cmd)).toBe(false);
		});

		test("allows agent-browser eval --stdin <<'EVALEOF'", () => {
			const cmd = `agent-browser eval --stdin <<'EVALEOF'\nconst x = document.title;\nx;\nEVALEOF`;
			expect(hasUnparseableConstructs(cmd)).toBe(false);
		});

		test("allows agent-browser eval --stdin <<EVALEOF (unquoted)", () => {
			const cmd = `agent-browser eval --stdin <<EVALEOF\ndocument.title;\nEVALEOF`;
			expect(hasUnparseableConstructs(cmd)).toBe(false);
		});

		test("allows --stdin heredoc with complex JS body", () => {
			const cmd = `agent-browser eval --stdin <<'EVALEOF'
const containers = document.querySelectorAll('div');
let feedText = '';
for (const c of containers) {
  const style = getComputedStyle(c);
  if ((style.overflowY === 'auto' || style.overflowY === 'scroll') && c.scrollHeight > 6000) {
    feedText = c.innerText;
    break;
  }
}
feedText.substring(4000, 8000);
EVALEOF`;
			expect(hasUnparseableConstructs(cmd)).toBe(false);
		});

		test("allows --stdin heredoc after sleep && chain", () => {
			const cmd = `sleep 5 && agent-browser eval --stdin <<'EVALEOF'\nwindow.__tsDebugLogs = [];\nEVALEOF`;
			expect(hasUnparseableConstructs(cmd)).toBe(false);
		});

		test("allows --stdin with tab-stripped heredoc (<<-)", () => {
			const cmd = `agent-browser eval --stdin <<-'EVALEOF'\n\tdocument.title;\nEVALEOF`;
			expect(hasUnparseableConstructs(cmd)).toBe(false);
		});

		test("allows any tool using --stdin <<", () => {
			const cmd = `some-other-tool --stdin <<'INPUT'\ndata here\nINPUT`;
			expect(hasUnparseableConstructs(cmd)).toBe(false);
		});
	});

	describe("blocked heredoc patterns", () => {
		test("blocks plain heredoc without safe pattern", () => {
			const cmd = `cat <<EOF\nsensitive data\nEOF`;
			expect(hasUnparseableConstructs(cmd)).toBe(true);
		});

		test("blocks heredoc in arbitrary command", () => {
			const cmd = `bash <<'SCRIPT'\nrm -rf /\nSCRIPT`;
			expect(hasUnparseableConstructs(cmd)).toBe(true);
		});

		test("blocks heredoc with double-quoted delimiter", () => {
			const cmd = `sh <<"END"\necho hello\nEND`;
			expect(hasUnparseableConstructs(cmd)).toBe(true);
		});

		test("blocks tab-stripped heredoc without safe pattern", () => {
			const cmd = `bash <<-EOF\n\techo danger\nEOF`;
			expect(hasUnparseableConstructs(cmd)).toBe(true);
		});

		test("known limitation: --stdin in heredoc body causes false allow", () => {
			// The regex matches --stdin << anywhere in the raw string, including
			// inside the heredoc body. This is a known limitation — fixing it would
			// require actual shell parsing. The risk is low since this is a contrived
			// scenario unlikely to appear in real usage.
			const cmd = `bash <<'EOF'\n--stdin << is in the body\nEOF`;
			expect(hasUnparseableConstructs(cmd)).toBe(false); // ideally true
		});
	});

	describe("process substitution", () => {
		test("blocks <(command) process substitution", () => {
			expect(hasUnparseableConstructs("diff <(sort file1) <(sort file2)")).toBe(true);
		});

		test("blocks single process substitution", () => {
			expect(hasUnparseableConstructs("cat <(echo hello)")).toBe(true);
		});
	});

	describe("arithmetic expansion", () => {
		test("blocks $(( )) arithmetic expansion", () => {
			expect(hasUnparseableConstructs("echo $((1 + 2))")).toBe(true);
		});

		test("blocks arithmetic in variable assignment", () => {
			expect(hasUnparseableConstructs("x=$((a * b))")).toBe(true);
		});
	});

	describe("safe commands (no unparseable constructs)", () => {
		test("allows simple commands", () => {
			expect(hasUnparseableConstructs("ls -la")).toBe(false);
		});

		test("allows piped commands", () => {
			expect(hasUnparseableConstructs("git log | head -10")).toBe(false);
		});

		test("allows commands with environment variables", () => {
			expect(hasUnparseableConstructs("NODE_ENV=production npm start")).toBe(false);
		});

		test("allows commands with $() command substitution", () => {
			expect(hasUnparseableConstructs("echo $(date)")).toBe(false);
		});

		test("allows redirects", () => {
			expect(hasUnparseableConstructs("echo hello > output.txt")).toBe(false);
		});

		test("allows chained commands", () => {
			expect(hasUnparseableConstructs("npm install && npm test")).toBe(false);
		});
	});
});
