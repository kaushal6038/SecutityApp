
$( document ).ready(function() {

	// $("#select-network option[id='"+ selected_network_id +"']").attr("selected", "selected");
	var selected_network_id;
	selected_network_id = $('#network_id').val();
	
	$('#select-network option').filter(function(){
	   return this.id === selected_network_id
	}).prop('selected', true);


	$('#select-network').on('change', function(){
		var network_id = $(this).val();
		if (network_id == "all_network"){
			window.location.href = '/nessus'
		}
		else{
			url = '/nessus/network/'+network_id;
	    	window.location.href = url
		}	
	});

});

