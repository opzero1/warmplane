# The House-Guest Benchmark

Imagine this.

You invite a friend over.

Instead of saying, “Want coffee?”, you trap them in the hallway and begin a 30-minute monologue:

- every appliance in your home,
- every drawer,
- every spice,
- every backup spice,
- and a deeply emotional history of your Wi-Fi router firmware.

Then, one hour later, you stare into their soul and ask:

“Quick question. In paragraph 6, line 14, what did I say about the replacement filter for the upstairs humidifier?”

If your friend leaves and never returns, that is not a social failure.
That is a protocol design lesson.

## Raw MCP, Unfiltered

A lot of agent tool setups do exactly this.

Before the model can do one useful thing, we hand it a giant encyclopedia of tools and schemas.
Then we wonder why costs spike, responses slow down, and the model occasionally hallucinates itself into a filing cabinet.

It is not that the model is bad.
It is that we made it sit through the world’s longest onboarding deck before asking it to fetch one document.

## The Better Conversation

`Warmplane` is the polite host.

It says:

“Here’s a short menu. Tell me what you want. I’ll bring details when needed.”

That’s it.

No 30-minute preamble.
No “remember slide 47.”
No schema dissertation before the first action.

## The Punchline Is Measured

From the eval harness:

- GitHub Copilot MCP scenarios: about **95.6% to 95.8%** token savings.
- Filesystem control scenario: about **58.1% to 58.2%** savings.

So yes, sometimes the difference between raw connectivity and compact capability planes is basically:

- “Please read this phone book every turn”
vs
- “Pick from this menu, and I’ll fetch details on demand.”

## Final Rule for Humans and Agents

If a human guest would call it rambling,
your model probably calls it context bloat.

Give both of them the short version first.
