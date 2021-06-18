

// Markers on the world map

function getScalling(country) {
	var coords = countryCoords[country]
	return {lat: coords[0], lng: coords[1], scale: 3, animate: true}
}
function identical(array) {
    for(var i = 0; i < array.length - 1; i++) {
        if(array[i] !== array[i+1]) {
            return false;
        }
    }
    return true;
}
$(function(){
	// var mapdata = mapdata.replace(/&quot;/g,'"')
	var plotlist = []
	var cities = []
	$.each(JSON.parse(mapdata.replace(/&quot;/g,'"')), function (i, item){
 		var latlng = {};
 		latlng.latLng = [item.fields.latitude, item.fields.longitude]
 		latlng.name = item.fields.city
 		cities.push(item.fields.city)
 		plotlist.push(latlng);
 	});
	$('#world-map-markers').vectorMap({
		map: 'world_mill_en',
		scaleColors: ['#6FB4CE', '#A9BD7A'],
		normalizeFunction: 'polynomial',
		hoverOpacity: 0.7,
		hoverColor: false,
		zoomOnScroll: false,
		markerStyle: {
			initial: {
				fill: '#E04747',
				stroke: '#FFFFFF',
				r: 4
			}
		},
		onRegionTipShow: function (e, label, code) {
    e.preventDefault();
	},
		zoomMin: 1,
		hoverColor: true,
		series: {
			regions: [{
				values: gdpData,
				scale: ['#89A4C1', '#959AB8'],
				normalizeFunction: 'polynomial'
			}]
		},
		backgroundColor: '#2a3039',
		markers: plotlist,
	});
	var mapObj = $('#world-map-markers').vectorMap('get', 'mapObject');
	if (plotlist.length == 1){
		plotelem = plotlist[0]
		focus = {scale:4, lat: plotelem.latLng[0], lng: plotelem.latLng[1], x: 0.5, y: 0.5, animate: true}
		mapObj.setFocus(focus)
	}
	else {
		if (identical(cities) == true) {
		    plotelem = plotlist[0]
			focus = {scale:4, lat: plotelem.latLng[0], lng: plotelem.latLng[1], x: 0.5, y: 0.5, animate: true}
			mapObj.setFocus(focus)
		}
		else if (identical(cities) == false){
			mapObj.setFocus({
				regions: country_code,
				animate: true
			})
		}

	}
});
