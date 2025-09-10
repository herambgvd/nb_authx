"""
Google Maps API Service for AuthX.
Provides location services including geocoding, reverse geocoding, and place details.
"""
import asyncio
import logging
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass
import httpx
import googlemaps
from googlemaps.exceptions import ApiError, Timeout, TransportError
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from app.core.config import settings

logger = logging.getLogger(__name__)

@dataclass
class LocationData:
    """Location data structure."""
    address: str
    latitude: float
    longitude: float
    place_id: Optional[str] = None
    formatted_address: Optional[str] = None
    country: Optional[str] = None
    state: Optional[str] = None
    city: Optional[str] = None
    postal_code: Optional[str] = None
    place_types: Optional[List[str]] = None

@dataclass
class PlaceDetails:
    """Place details structure."""
    place_id: str
    name: str
    formatted_address: str
    latitude: float
    longitude: float
    phone_number: Optional[str] = None
    website: Optional[str] = None
    rating: Optional[float] = None
    business_status: Optional[str] = None
    types: Optional[List[str]] = None

class GoogleMapsService:
    """Google Maps API service with async support and error handling."""

    def __init__(self):
        self.api_key = settings.GOOGLE_MAPS_API_KEY
        self.timeout = settings.GOOGLE_API_TIMEOUT
        self.retry_attempts = settings.GOOGLE_API_RETRY_ATTEMPTS

        # Don't initialize client immediately to prevent startup failures
        self.client = None
        self._client_initialized = False

        # HTTP client for async requests
        self.http_client = httpx.AsyncClient(timeout=self.timeout)

    def _init_client(self):
        """Initialize Google Maps client lazily."""
        if self._client_initialized:
            return

        if not self.api_key or self.api_key == "your-google-maps-api-key":
            logger.warning("Google Maps API key not configured or using default placeholder")
            self.client = None
        else:
            try:
                self.client = googlemaps.Client(key=self.api_key)
                logger.info("Google Maps client initialized successfully")
            except Exception as e:
                logger.warning(f"Failed to initialize Google Maps client: {e}")
                self.client = None

        self._client_initialized = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.http_client.aclose()

    def _check_api_key(self):
        """Check if API key is configured."""
        if not self.api_key:
            raise ValueError("Google Maps API key not configured")

    @retry(
        retry=retry_if_exception_type((ApiError, Timeout, TransportError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10)
    )
    async def geocode_address(self, address: str) -> Optional[LocationData]:
        """
        Geocode an address to get latitude and longitude.

        Args:
            address: Address to geocode

        Returns:
            LocationData object with coordinates and details
        """
        self._check_api_key()
        self._init_client()

        try:
            # Run in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self.client.geocode(address)
            )

            if not result:
                logger.warning(f"No geocoding results for address: {address}")
                return None

            location_data = result[0]
            geometry = location_data['geometry']['location']

            # Extract address components
            components = self._extract_address_components(
                location_data.get('address_components', [])
            )

            return LocationData(
                address=address,
                latitude=geometry['lat'],
                longitude=geometry['lng'],
                place_id=location_data.get('place_id'),
                formatted_address=location_data.get('formatted_address'),
                country=components.get('country'),
                state=components.get('administrative_area_level_1'),
                city=components.get('locality'),
                postal_code=components.get('postal_code'),
                place_types=location_data.get('types', [])
            )

        except Exception as e:
            logger.error(f"Error geocoding address '{address}': {str(e)}")
            raise

    @retry(
        retry=retry_if_exception_type((ApiError, Timeout, TransportError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10)
    )
    async def reverse_geocode(self, latitude: float, longitude: float) -> Optional[LocationData]:
        """
        Reverse geocode coordinates to get address.

        Args:
            latitude: Latitude coordinate
            longitude: Longitude coordinate

        Returns:
            LocationData object with address details
        """
        self._check_api_key()
        self._init_client()

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self.client.reverse_geocode((latitude, longitude))
            )

            if not result:
                logger.warning(f"No reverse geocoding results for coordinates: {latitude}, {longitude}")
                return None

            location_data = result[0]

            # Extract address components
            components = self._extract_address_components(
                location_data.get('address_components', [])
            )

            return LocationData(
                address=location_data.get('formatted_address', ''),
                latitude=latitude,
                longitude=longitude,
                place_id=location_data.get('place_id'),
                formatted_address=location_data.get('formatted_address'),
                country=components.get('country'),
                state=components.get('administrative_area_level_1'),
                city=components.get('locality'),
                postal_code=components.get('postal_code'),
                place_types=location_data.get('types', [])
            )

        except Exception as e:
            logger.error(f"Error reverse geocoding coordinates {latitude}, {longitude}: {str(e)}")
            raise

    @retry(
        retry=retry_if_exception_type((ApiError, Timeout, TransportError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10)
    )
    async def get_place_details(self, place_id: str) -> Optional[PlaceDetails]:
        """
        Get detailed information about a place.

        Args:
            place_id: Google Places API place ID

        Returns:
            PlaceDetails object with comprehensive place information
        """
        self._check_api_key()
        self._init_client()

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self.client.place(
                    place_id=place_id,
                    fields=[
                        'name', 'formatted_address', 'geometry', 'formatted_phone_number',
                        'website', 'rating', 'business_status', 'types'
                    ]
                )
            )

            if not result or 'result' not in result:
                logger.warning(f"No place details found for place_id: {place_id}")
                return None

            place_data = result['result']
            geometry = place_data.get('geometry', {}).get('location', {})

            return PlaceDetails(
                place_id=place_id,
                name=place_data.get('name', ''),
                formatted_address=place_data.get('formatted_address', ''),
                latitude=geometry.get('lat', 0.0),
                longitude=geometry.get('lng', 0.0),
                phone_number=place_data.get('formatted_phone_number'),
                website=place_data.get('website'),
                rating=place_data.get('rating'),
                business_status=place_data.get('business_status'),
                types=place_data.get('types', [])
            )

        except Exception as e:
            logger.error(f"Error getting place details for place_id '{place_id}': {str(e)}")
            raise

    @retry(
        retry=retry_if_exception_type((ApiError, Timeout, TransportError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10)
    )
    async def search_places(
        self,
        query: str,
        location: Optional[Tuple[float, float]] = None,
        radius: int = 50000  # 50km default
    ) -> List[PlaceDetails]:
        """
        Search for places using text query.

        Args:
            query: Search query (e.g., "restaurants near me")
            location: Optional (latitude, longitude) for location bias
            radius: Search radius in meters

        Returns:
            List of PlaceDetails objects
        """
        self._check_api_key()
        self._init_client()

        try:
            loop = asyncio.get_event_loop()

            if location:
                result = await loop.run_in_executor(
                    None,
                    lambda: self.client.places_nearby(
                        location=location,
                        radius=radius,
                        keyword=query
                    )
                )
            else:
                result = await loop.run_in_executor(
                    None,
                    lambda: self.client.places(query=query)
                )

            places = []
            for place_data in result.get('results', []):
                geometry = place_data.get('geometry', {}).get('location', {})

                place_details = PlaceDetails(
                    place_id=place_data.get('place_id', ''),
                    name=place_data.get('name', ''),
                    formatted_address=place_data.get('formatted_address', ''),
                    latitude=geometry.get('lat', 0.0),
                    longitude=geometry.get('lng', 0.0),
                    phone_number=place_data.get('formatted_phone_number'),
                    website=place_data.get('website'),
                    rating=place_data.get('rating'),
                    business_status=place_data.get('business_status'),
                    types=place_data.get('types', [])
                )
                places.append(place_details)

            return places

        except Exception as e:
            logger.error(f"Error searching places with query '{query}': {str(e)}")
            raise

    async def validate_coordinates(self, latitude: float, longitude: float) -> bool:
        """
        Validate if coordinates are valid by attempting reverse geocoding.

        Args:
            latitude: Latitude coordinate
            longitude: Longitude coordinate

        Returns:
            True if coordinates are valid, False otherwise
        """
        try:
            result = await self.reverse_geocode(latitude, longitude)
            return result is not None
        except Exception:
            return False

    def _extract_address_components(self, components: List[Dict[str, Any]]) -> Dict[str, str]:
        """
        Extract address components from Google Maps API response.

        Args:
            components: Address components from API response

        Returns:
            Dictionary with extracted components
        """
        extracted = {}

        for component in components:
            types = component.get('types', [])
            long_name = component.get('long_name', '')
            short_name = component.get('short_name', '')

            if 'country' in types:
                extracted['country'] = long_name
                extracted['country_code'] = short_name
            elif 'administrative_area_level_1' in types:
                extracted['administrative_area_level_1'] = long_name
                extracted['state'] = long_name
            elif 'administrative_area_level_2' in types:
                extracted['administrative_area_level_2'] = long_name
            elif 'locality' in types:
                extracted['locality'] = long_name
                extracted['city'] = long_name
            elif 'sublocality' in types:
                extracted['sublocality'] = long_name
            elif 'postal_code' in types:
                extracted['postal_code'] = long_name
            elif 'route' in types:
                extracted['route'] = long_name
            elif 'street_number' in types:
                extracted['street_number'] = long_name

        return extracted

    async def calculate_distance(
        self,
        origin: Tuple[float, float],
        destination: Tuple[float, float]
    ) -> Optional[Dict[str, Any]]:
        """
        Calculate distance and duration between two points.

        Args:
            origin: (latitude, longitude) of origin
            destination: (latitude, longitude) of destination

        Returns:
            Dictionary with distance and duration information
        """
        self._check_api_key()
        self._init_client()

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self.client.distance_matrix(
                    origins=[origin],
                    destinations=[destination],
                    units="metric"
                )
            )

            if (result and 'rows' in result and result['rows'] and
                'elements' in result['rows'][0] and result['rows'][0]['elements']):

                element = result['rows'][0]['elements'][0]

                if element['status'] == 'OK':
                    return {
                        'distance': {
                            'text': element['distance']['text'],
                            'value': element['distance']['value']  # in meters
                        },
                        'duration': {
                            'text': element['duration']['text'],
                            'value': element['duration']['value']  # in seconds
                        }
                    }

            return None

        except Exception as e:
            logger.error(f"Error calculating distance: {str(e)}")
            raise

# Global service instance
google_maps_service = GoogleMapsService()
