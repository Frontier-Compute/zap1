# Zkool ZAP1 Memo Plugin

Zkool supports memo plugins through its Plugin Manager. This package renders
ZAP1 structured memo strings such as:

```text
ZAP1:01:075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b
```

It matches the `ZAP1` prefix, labels known type bytes, keeps the raw hash
visible, and links non-root entries to the ZAP1 proof endpoint.

Install URL after this lands on `main`:

```text
https://github.com/Frontier-Compute/zap1/raw/main/plugins/zkool/zap1-memo-plugin.zip
```

Source files are under `plugins/zkool/zap1-memo-plugin/`. The zip is flat
because Zkool expects `manifest.json` and `main.rhai` at archive root.
