# Service Areas and Service Industries Filter Examples

## Service Areas Endpoints

### Admin Endpoint: `GET /api/user/service-areas/`
**Permission:** Admin only

### Public Endpoint: `GET /api/user/public/service-areas/`
**Permission:** Public (no authentication required)

### Available Filters:

1. **Filter by Active Status**
   ```
   GET /api/user/service-areas/?is_active=true
   GET /api/user/service-areas/?is_active=false
   GET /api/user/public/service-areas/?is_active=true
   ```

2. **Search by Name** (case-insensitive partial match)
   ```
   GET /api/user/service-areas/?search=cleaning
   GET /api/user/service-areas/?search=area
   GET /api/user/public/service-areas/?search=test
   ```

3. **Ordering** (use `-` prefix for descending)
   ```
   GET /api/user/service-areas/?ordering=name
   GET /api/user/service-areas/?ordering=-created_at
   GET /api/user/service-areas/?ordering=updated_at
   GET /api/user/public/service-areas/?ordering=-name
   ```

4. **Combined Filters**
   ```
   GET /api/user/service-areas/?is_active=true&search=area&ordering=name
   GET /api/user/public/service-areas/?is_active=true&search=test&ordering=-created_at
   ```

---

## Service Industries Endpoints

### Admin Endpoint: `GET /api/user/service-industries/`
**Permission:** Admin only

### Public Endpoint: `GET /api/user/public/service-industries/`
**Permission:** Public (no authentication required)

### Available Filters:

1. **Filter by Active Status**
   ```
   GET /api/user/service-industries/?is_active=true
   GET /api/user/service-industries/?is_active=false
   GET /api/user/public/service-industries/?is_active=true
   ```

2. **Search by Name** (case-insensitive partial match)
   ```
   GET /api/user/service-industries/?search=cleaning
   GET /api/user/service-industries/?search=inspection
   GET /api/user/public/service-industries/?search=repair
   ```

3. **Filter by Price Range**
   ```
   GET /api/user/service-industries/?min_price=50
   GET /api/user/service-industries/?max_price=200
   GET /api/user/service-industries/?min_price=50&max_price=200
   GET /api/user/public/service-industries/?min_price=100&max_price=500
   ```

4. **Ordering** (use `-` prefix for descending)
   ```
   GET /api/user/service-industries/?ordering=name
   GET /api/user/service-industries/?ordering=price
   GET /api/user/service-industries/?ordering=-price
   GET /api/user/service-industries/?ordering=-created_at
   GET /api/user/public/service-industries/?ordering=price
   ```

5. **Combined Filters**
   ```
   GET /api/user/service-industries/?is_active=true&search=cleaning&min_price=50&max_price=200&ordering=price
   GET /api/user/public/service-industries/?is_active=true&search=inspection&min_price=100&ordering=-price
   GET /api/user/service-industries/?is_active=true&min_price=50&max_price=150&ordering=name
   ```

---
   Service Industries:
   GET /api/user/service-industries/?is_active=true&search=cleaning&min_price=50&max_price=200&ordering=price
   GET /api/user/public/service-industries/?is_active=true&search=inspection&min_price=100&ordering=-price


   Service Area:
   GET /api/user/service-areas/?is_active=true&search=area&ordering=name
   GET /api/user/public/service-areas/?is_active=true&search=test&ordering=-created_at

## Example Responses

### Service Areas Response:
```json
[
  {
    "id": 1,
    "name": "Test Area 1",
    "is_active": true,
    "created_at": "2025-01-15T10:30:00Z",
    "updated_at": "2025-01-15T10:30:00Z"
  },
  {
    "id": 2,
    "name": "Service Area 2",
    "is_active": true,
    "created_at": "2025-01-15T11:00:00Z",
    "updated_at": "2025-01-15T11:00:00Z"
  }
]
```

### Service Industries Response:
```json
[
  {
    "id": 1,
    "name": "Chimney Inspection",
    "price": "200.00",
    "is_active": true,
    "created_at": "2025-01-15T10:30:00Z",
    "updated_at": "2025-01-15T10:30:00Z"
  },
  {
    "id": 2,
    "name": "Window Cleaning",
    "price": "150.00",
    "is_active": true,
    "created_at": "2025-01-15T11:00:00Z",
    "updated_at": "2025-01-15T11:00:00Z"
  }
]
```

---

## Notes

- All filters can be combined using `&` separator
- Search is case-insensitive and matches partial strings
- Price filters accept decimal values
- Ordering fields: `name`, `price` (industries only), `created_at`, `updated_at`, `id`
- Use `-` prefix for descending order (e.g., `-price`, `-created_at`)
- Public endpoints default to `is_active=true` if not specified
- Admin endpoints return all records by default (no filter applied)

