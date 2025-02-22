import os
from pathlib import Path
import time

import click
import click_repl

from tqdm import tqdm

from oxen_wallet_cli import context

import pywallet3

OXEN_ATOMIC_UNITS = 1e9

@click.group(invoke_without_command=True)
@click.option('--log-level', type=click.Choice(['error', 'warn', 'info', 'debug']), default="info")
@click.option('--network', default='testnet', type=click.Choice(['mainnet', 'testnet', 'devnet'], case_sensitive=False), help='Network: mainnet|testnet|devnet.')
@click.option('--oxend-url', default="ipc:///home/sean/.oxen/testnet/oxend.sock", type=str, help='Use the given daemon')
@click.option('--datadir', help='A directory which the wallet will save data')
@click.option('--rounding', help='how many decimal places will be displayed for oxen', type=int, default=2)
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
        click.echo("Oxen wallet started, you will need to load a wallet to continue")
        click.echo("Please use load-from-file or load-from-seed")
        click.echo("Run 'help' for help information, or 'quit' to quit.")
        click_repl.repl(click_ctx)

def progress_bar():
    click.echo("Starting Wallet Sync")
    with tqdm(total=1, ncols = 80, nrows = 3, position = 0, leave=False, unit="blocks", colour="green") as pbar:
        syncing = True
        retries = 10
        prev_height = 0
        while syncing and retries > 0:
            try:
                status_future = context.rpc_future("rpc.status");
                status_response = status_future.get();
                pbar.total = status_response["target_height"]
                pbar.update(status_response["sync_height"] - prev_height)
                prev_height = status_response["sync_height"]
                syncing = status_response["syncing"]
                time.sleep(0.5)
            except Excepiton as e:
                retries -= 1
    click.echo("Wallet Synced")
    pbar.close()

def display_status():
    status_future = context.rpc_future("rpc.status");
    status_response = status_future.get();
    if status_response["syncing"]:
        progress_bar()
    else:
        click.echo("Wallet Synced")

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
    click.echo("Wallet address " + click.style("{}", fg='cyan', bold=True).format(keyring.get_main_address()) + " loaded")
    if context.options['wallet_name'] is None:
        name = click.prompt("Wallet Name", default="{}-oxen-wallet".format(context.options["network"])).strip()
    else:
        name = context.options['wallet_name']
    context.wallet_core_config.omq_rpc.sockname = name + ".sock";
    context.wallet = pywallet3.Wallet(name, keyring, context.wallet_core_config)
    context.omq_connection()
    display_status()

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
    context.omq_connection()
    display_status()

@walletcli.command()
def load_from_file():
    click.echo("Loading wallet from file")
    if context.wallet is not None:
        click.echo("Wallet already loaded")
        return

    keyring = None
    if context.options['wallet_name'] is None:
        name = click.prompt("Wallet Name", default="{}-oxen-wallet".format(context.options["network"])).strip()
    else:
        name = context.options['wallet_name']
    context.wallet_core_config.omq_rpc.sockname = name + ".sock";
    context.wallet = pywallet3.Wallet(name, keyring, context.wallet_core_config)
    context.omq_connection()
    display_status()

@walletcli.command()
def register_service_node():
    click.echo("Registering Service Node")
    if click.confirm("Would you like to register a service node now"):
        click.echo("")
        name = click.prompt("Enter the wallet address of the operator", default="").strip()
        click.echo("The wallet address to be used is: {}".format(name))
        click.echo("TODO: This function is not yet implemented")

@walletcli.command()
def status():
    if context.wallet is None:
        click.echo("Wallet not loaded")
        return
    status_future = context.rpc_future("rpc.status");
    status_response = status_future.get();
    click.echo("Status: {}".format(status_response))

@walletcli.command()
def address():
    if context.wallet is None:
        click.echo("Wallet not loaded")
        return
    get_address_future = context.rpc_future("rpc.get_address");
    get_address_response = get_address_future.get();
    address = get_address_response['address']
    click.echo("Address: {}".format(address))

@walletcli.command()
def balance():
    if context.wallet is None:
        click.echo("Wallet not loaded")
        return
    get_balance_future = context.rpc_future("rpc.get_balance");
    get_balance_response = get_balance_future.get();
    balance = get_balance_response['balance']
    click.echo("Balance: {:.{oxen_precision}f} Oxen".format(balance/OXEN_ATOMIC_UNITS, oxen_precision=context.options["rounding"]))

@walletcli.command()
def unlocked_balance():
    if context.wallet is None:
        click.echo("Wallet not loaded")
        return
    get_balance_future = context.rpc_future("rpc.get_balance");
    get_balance_response = get_balance_future.get();
    unlocked_balance = get_balance_response['unlocked_balance']
    click.echo("Unlocked Balance: {:.{oxen_precision}f} Oxen".format(unlocked_balance/OXEN_ATOMIC_UNITS, oxen_precision=context.options["rounding"]))

@walletcli.command()
def height():
    height_future = context.rpc_future("rpc.get_height");
    height = height_future.get();
    click.echo("Height: {}".format(height))

@walletcli.command()
def transfer():
    address = click.prompt("Enter the destination wallet address", default="").strip()
    amount = click.prompt("Enter the amount in oxen to be sent to {}".format(address), default=0.0)
    if address == "" or amount == 0.0:
        click.prompt("Invalid address/amount entered")
        return
    amount_in_atomic_units = round(amount * OXEN_ATOMIC_UNITS, 0);
    destination = {"address": address, "amount": amount_in_atomic_units}
    transfer_params = {"destinations": [destination]}
    transfer_future = context.rpc_future("restricted.transfer", args=transfer_params);
    transfer_response = transfer_future.get();
    click.echo("Transfer Response: {}".format(transfer_response))

lokinet_years_dict = {"1": "lokinet", "2": "lokinet_2years", "5": "lokinet_5years", "10": "lokinet_10years"}

# TODO better names for these ONS commands
@walletcli.command()
def ons_buy_mapping():
    ons_type = click.prompt("What type of mapping would you like", type=click.Choice(['session', 'wallet', 'lokinet']), default="session").strip()
    if ons_type == "lokinet":
        lokinet_years = click.prompt("How many years would you like the lokinet mapping for?", type=click.Choice(["1", "2", "5", "10"]), default="1").strip()
        ons_type = lokinet_years_dict[lokinet_years]

    ons_name = click.prompt("Please enter the ons name you would like to register", default="").strip()
    ons_value = click.prompt("Please enter the value for the ons mapping", default="").strip()
    ons_buy_params = {
            "name": ons_name,
            "value": ons_value,
            "type": ons_type,
           }
    ons_owner = click.prompt("Optional: Enter the address of a different owner", default="").strip()
    if len(ons_owner) > 0:
        ons_buy_params["owner"] = ons_owner
    ons_backup_owner = click.prompt("Optional: Enter the address of a backup owner", default="").strip()
    if len(ons_backup_owner) > 0:
        ons_buy_params["backup_owner"] = ons_backup_owner

    transfer_future = context.rpc_future("restricted.ons_buy_mapping", args=ons_buy_params);
    transfer_response = transfer_future.get();
    click.echo("ONS Buy Mapping Response: {}".format(transfer_response))

# TODO better names for these ONS commands
@walletcli.command()
def ons_update_mapping():
    ons_name = click.prompt("Please enter the ons name you would like to update", default="").strip()
    ons_type = click.prompt("Please enter the type of ONS mapping this is", type=click.Choice(['session', 'wallet', 'lokinet', 'lokinet_2years', 'lokinet_5years', 'lokinet_10years']), default="session").strip()
    ons_update_params = {
            "name": ons_name,
            "type": ons_type,
           }
    ons_value = click.prompt("Optional: Please enter a value to modify the ons mapping", default="").strip()
    if len(ons_value) > 0:
        ons_buy_params["value"] = ons_value
    ons_owner = click.prompt("Optional: Please enter an address to modify the owner", default="").strip()
    if len(ons_owner) > 0:
        ons_buy_params["owner"] = ons_owner
    ons_backup_owner = click.prompt("Optional: Please enter an address to modify the backup owner", default="").strip()
    if len(ons_backup_owner) > 0:
        ons_buy_params["backup_owner"] = ons_backup_owner

    transfer_future = context.rpc_future("restricted.ons_update_mapping", args=ons_update_params);
    transfer_response = transfer_future.get();
    click.echo("ONS Update Mapping Response: {}".format(transfer_response))

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
