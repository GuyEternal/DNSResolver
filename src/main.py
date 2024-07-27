import socket
from classdefs import *
from serialize import *
from io import BytesIO
from parse import *
from utils import decode_dns_name
from resolve_utils import *
from rich.console import Console
from rich.prompt import Prompt
from rich.text import Text
from rich.panel import Panel
from rich.progress import Progress
from time import sleep, time

console = Console()
ROOT_SERVER_IP = "198.41.0.4"

def resolve_recursive(query_server, domain_name, record_type: Type):
    try:
        response = lookup_domain(query_server, domain_name, record_type, True)
        if response:
            if response._Header.ANCOUNT > 0:
                ip = get_answer(response, record_type.value)
                return ip
            else:
                rcode = response._Header.get_rcode()
                console.print(f"[bold yellow]No answer found in the response for {domain_name}. Error Code: {rcode}[/bold yellow]")
                if response._Header.NSCOUNT > 0:
                    ns_domain = get_nameserver(response)
                    if ns_domain:
                        console.print(f"[bold cyan]Found NS record: {ns_domain}[/bold cyan]")
                        return resolve_recursive(ROOT_SERVER_IP, ns_domain, record_type)
        else:
            console.print(f"[bold red]No response received for {domain_name}[/bold red]")
    except Exception as e:
        console.print(f"[bold red]Error querying {query_server}: {str(e)}[/bold red]")

def resolve_iterative(query_server, domain_name, record_type: Type, max_iterations=10, timeout=10, progress=None):
    nameserver = query_server
    start_time = time()
    task = progress.add_task("[cyan]Resolving...", total=max_iterations) if progress else None
    
    def worker():
        nonlocal nameserver
        for i in range(max_iterations):
            elapsed_time = time() - start_time
            if elapsed_time > timeout:
                console.print(f"[bold red]Error: Resolution timed out for {domain_name}[/bold red]")
                return "IP not found"

            console.print(f"[bold blue]Iteration {i}: Querying {nameserver} for {domain_name} (type {record_type})...[/bold blue]")
            try:
                response = lookup_domain(nameserver, domain_name, record_type, False)
            except Exception as e:
                console.print(f"[bold red]Error querying {nameserver}: {str(e)}[/bold red]")
                nameserver = ROOT_SERVER_IP  # Fallback to root server
                if progress: progress.update(task, advance=1)
                continue

            if response is None:
                console.print(f"[bold red]No response from {nameserver}[/bold red]")
                nameserver = ROOT_SERVER_IP  # Fallback to root server
                if progress: progress.update(task, advance=1)
                continue

            if response._Header.get_rcode() == 3:
                return f"[bold red]Error: Domain {domain_name} does not exist.[/bold red]"

            if response._Header.ANCOUNT > 0:
                ip = get_answer(response, record_type.value)
                if progress: progress.update(task, completed=100)  # Ensure progress bar completes
                return ip

            elif response._Header.NSCOUNT > 0:
                ns_domain = get_nameserver(response)
                if ns_domain is None:
                    console.print(f"[bold yellow]No usable NS records found for {domain_name}. Falling back to root server.[/bold yellow]")
                    nameserver = ROOT_SERVER_IP
                    if progress: progress.update(task, advance=1)
                    continue
                console.print(f"[bold cyan]Got the nameserver domain: {ns_domain}[/bold cyan]")

                if response._Header.ARCOUNT > 0:
                    nsIP = get_nameserver_ip_from_additional_section(response)
                    if nsIP:
                        console.print(f"[bold cyan]Got the nameserver IP from the Additional section: {nsIP}[/bold cyan]")
                        nameserver = nsIP
                        if progress: progress.update(task, advance=1)
                        continue

                console.print(f"[bold cyan]Resolving IP for nameserver {ns_domain}...[/bold cyan]")
                nsIP = resolve_iterative(ROOT_SERVER_IP, ns_domain, Type.A, timeout=timeout, progress=progress)
                if isinstance(nsIP, str) and not nsIP.startswith("Error"):
                    console.print(f"[bold cyan]Resolved nameserver IP: {nsIP}[/bold cyan]")
                    nameserver = nsIP
                else:
                    console.print(f"[bold red]Failed to resolve nameserver IP: {nsIP}[/bold red]")
                    nameserver = ROOT_SERVER_IP  # Fallback to root server
            else:
                console.print(f"[bold yellow]No answer or nameserver information in response[/bold yellow]")
                nameserver = ROOT_SERVER_IP  # Fallback to root server

            if progress: progress.update(task, advance=1)

        return "IP not found"
    
    return worker()

def lookup_domain(ip_address, domain_name, type: Type, recursion):
    query = build_query(domain_name, type, recursion)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, (ip_address, 53))
    data, _ = sock.recvfrom(1024)
    msg_response_obj = parse_dns_packet(data)
    return msg_response_obj

def build_query(domain_name, qtype, recursion):
    flags = QR.QUERY.value << 15 | OPCODE.QUERY.value << 11
    if recursion:
        flags |= RD.RECURSION_DESIRED.value << 8
    else:
        flags |= RD.RECURSION_NOT_DESIRED.value << 8

    msg = Message(
        Header(
            id=0x8298,
            flags=flags,
            QDCOUNT=1,
            ANCOUNT=0,
            NSCOUNT=0,
            ARCOUNT=0
        ),
        Question(
            QNAME=domain_name,
            QTYPE=Type(qtype),
            QCLASS=Class.IN
        ),
        None,
        None,
        None
    )
    return serialize_query_message(msg)

def main():
    # Display welcome panel with spinner animation
    console.print(Panel(
        Text.from_markup("[bold yellow]Welcome to the DNS Query Tool[/bold yellow]"),
        title="[bold magenta]DNS Query Tool[/bold magenta]",
        subtitle="[bold cyan]Choose your options below:[/bold cyan]",
        title_align="center",
        subtitle_align="center",
        border_style="bright_cyan",
        expand=True
    ))

    with console.status("[bold cyan]Loading options...[/bold cyan]", spinner="dots") as status:
        sleep(1.3)  # Simulate loading time

    query_model = Prompt.ask(
        Text.from_markup("[bold cyan]Select the query model[/bold cyan]"),
        choices=["iterative", "recursive"],
        default="iterative"
    )
    query_type = Prompt.ask(
        Text.from_markup("[bold cyan]Select the type of IP 'A' for IPv4 and 'AAAA' for IPv6[/bold cyan]"),
        choices=["A", "AAAA", "NS"],
        default="A"
    )
    domain_name = Prompt.ask(
        Text.from_markup("[bold cyan]Enter the domain name for which the IP is required[/bold cyan]")
    )

    console.print("[bold green]Processing your request...[/bold green]")

    with Progress() as progress:
        result = "IP not found"
        if query_model == "recursive":
            result = resolve_recursive("1.1.1.1", domain_name, Type[query_type])
        elif query_model == "iterative":
            result = resolve_iterative(ROOT_SERVER_IP, domain_name, Type[query_type], timeout=10, progress=progress)
        elif query_model == "NS":
            ns_domain = get_nameserver(lookup_domain(ROOT_SERVER_IP, domain_name, Type[query_type], False))
            result = ns_domain if ns_domain else "No NS record found"

        # Ensure the progress bar completes before displaying the result
        task = progress.add_task("[cyan]Completing...[bold cyan] 100%[/bold cyan]", total=100)
        while not progress.finished:
            progress.update(task, advance=1)
            sleep(0.05)  # Small delay to simulate progress completion

    console.print(Panel(
        Text.from_markup(f"[bold magenta]The resolved IP address for {domain_name} is:[/bold magenta] [bold white]{result}[/bold white]"),
        title="[bold blue]Result[/bold blue]",
        border_style="bright_green",
        expand=False
    ))

if __name__ == '__main__':
    main()
