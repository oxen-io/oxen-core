import os
from pathlib import Path

import click
import click_repl

from oxen_wallet_cli import context

import pywallet3

@click.group(invoke_without_command=True)
@click.option('--log-level', type=click.Choice(['error', 'warn', 'info', 'debug']), default="info")
@click.option('--network', default='testnet', type=click.Choice(['mainnet', 'testnet', 'devnet'], case_sensitive=False), help='Network: mainnet|testnet|devnet.')
@click.option('--oxend-url', default="ipc:///home/sean/.oxen/testnet/oxend.sock", type=str, help='Use the given daemon')
@click.option('--datadir', help='A directory which the wallet will save data')
@click.option('--append-network-to-datadir', default=True)
@click.option('--wallet-name')
# @click.option('--wallet-password')
@click.pass_context
def walletcli(click_ctx, **options):
    """Command line interface for Oxen Wallet CLI."""
    if context.configured:
        # In repl mode run configuration once only
        return

    if options['datadir'] is None:
        home = str(Path.home())
        options['datadir'] = os.path.expanduser(os.path.join(home, '.oxen-wallet'))

    os.makedirs(options['datadir'], exist_ok=True)
    if options['append_network_to_datadir']:
        os.makedirs(os.path.expanduser(os.path.join(options['datadir'], options['network'])), exist_ok=True)

    context.configure(options)

    if click_ctx.invoked_subcommand is None:
        click.echo("Run 'help' for help information, or 'quit' to quit.")
        click_repl.repl(click_ctx)

@walletcli.command()
def load_test_wallet():
    click.echo("Loading test wallet")
    if context.wallet is not None:
        click.echo("Wallet already loaded")
        return

    spend_priv = "e6c9165356c619a64a0d26fafd99891acccccf8717a8067859d972ecd8bcfc0a"
    spend_pub = "b76f2d7c8a036ff65c564dcb27081c04fe3f2157942e23b0496ca797ba728e4f"
    view_priv = "961d67bb5b3ed1af8678bbfcf621f9c15c2b7bff080892890020bdfd47fe4f0a"
    view_pub = "8a0ebacd613e0b03b8f27bc64bd961ea2ebf4c671c6e7f3268651acf0823fed5"

    keyring = pywallet3.Keyring(spend_priv, spend_pub, view_priv, view_pub, context.options["network"])
    click.echo("Wallet address {} loaded".format(keyring.get_main_address()))
    if context.options['wallet_name'] is None:
        name = click.prompt("Wallet Name", default="{}-oxen-wallet".format(context.options["network"])).strip()
    else:
        name = context.options['wallet_name']
    context.wallet_core_config.omq_rpc.sockname = name + ".sock";
    context.wallet = pywallet3.Wallet(name, keyring, context.wallet_core_config)

@walletcli.command()
@click.argument('seed_phrase', nargs=25)
@click.argument('seed_phrase_passphrase', default="")
def load_from_seed(seed_phrase, seed_phrase_passphrase):
    click.echo("Loading wallet from seed")
    if context.wallet is not None:
        click.echo("Wallet already loaded")
        return

    seed_phrase_str = ' '.join(seed_phrase)
    keyring = context.keyring_manager.generate_keyring_from_electrum_seed(seed_phrase_str, seed_phrase_passphrase)
    click.echo("Wallet address {} loaded".format(keyring.get_main_address()))
    if context.options['wallet_name'] is None:
        name = click.prompt("Wallet Name", default="{}-oxen-wallet".format(context.options["network"])).strip()
    else:
        name = context.options['wallet_name']
    context.wallet_core_config.omq_rpc.sockname = name + ".sock";
    context.wallet = pywallet3.Wallet(name, keyring, context.wallet_core_config)

@walletcli.command()
def register_service_node():
    click.echo("Registering Service Node")
    if click.confirm("Would you like to register a service node now"):
        click.echo("")
        name = click.prompt("Enter the wallet address of the operator", default="").strip()
        click.echo("The wallet address to be used is: {}".format(name))
        click.echo("TODO: This function is not yet implemented")

@walletcli.command()
def address():
    # click.echo("Address: {}".format(context.keyring.get_main_address()))
    click.echo("Address: {}".format("TODO sean get the address here"))

@walletcli.command()
def get_balance():
    click.echo("Balance: {}".format(context.wallet.get_balance()))

@walletcli.command()
def get_unlocked_balance():
    click.echo("Unlocked Balance: {}".format(context.wallet.get_unlocked_balance()))

@walletcli.command()
def quit():
    if context.wallet:
        context.wallet.deregister()
    click_repl.exit()

@walletcli.command()
def help():
    click.echo("TODO help")

def main():
    walletcli()
