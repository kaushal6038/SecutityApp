$( document ).ready(function() {
	if (s3_pass_percentage == 100){
		var fg_round_color = '#1f6d24';
	}
	else{
		var fg_round_color = '#BF7A6A';
	}
	$("#s3_security_overview").circliful({
			animation: 1,
			animationStep: 5,
			foregroundBorderWidth: 15,
			backgroundBorderWidth: 15,
			percent: s3_pass_percentage,
			fontColor: '#b3bdcc',
			foregroundColor: fg_round_color,
			backgroundColor: '#353c48',
			multiPercentage: 1,
			percentages: [10, 20, 30]
	});
	$("#aws_api_gateways").circliful({
			animation: 1,
			animationStep: 5,
			foregroundBorderWidth: 15,
			backgroundBorderWidth: 15,
			percent: 100,
			fontColor: '#b3bdcc',
			foregroundColor: '#1f6d24',
			backgroundColor: '#353c48',
			multiPercentage: 1,
			percentages: [10, 20, 30]
	});
	$("#aws_rds_databases").circliful({
			animation: 1,
			animationStep: 5,
			foregroundBorderWidth: 15,
			backgroundBorderWidth: 15,
			percent: 100,
			fontColor: '#b3bdcc',
			foregroundColor: '#1f6d24',
			backgroundColor: '#353c48',
			multiPercentage: 1,
			percentages: [10, 20, 30]
	});
});