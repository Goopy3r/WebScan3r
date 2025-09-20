def scan(self, url):
    print(CONFIG["BANNER"])
    
    # Normalize the URL - add https:// if no scheme is provided
    try:
        normalized_url = self.normalize_url(url)
        self.print_status(f"Starting scan for: {normalized_url}", "info")

        if not self.validate_url(normalized_url):
            self.print_status("Invalid URL format", "error")
            return

        # Check if URL contains /FUZZ/ and only run WFuzz if it does
        if "/FUZZ/" in normalized_url.upper():
            self.print_status("FUZZ pattern detected, running WFuzz only", "info")
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                loop.run_until_complete(self.run_wfuzz_only(normalized_url))
            except KeyboardInterrupt:
                self.print_status("Scan interrupted by user", "warning")
            finally:
                try:
                    if self.aiohttp_session:
                        loop.run_until_complete(self.aiohttp_session.close())
                    loop.close()
                except:
                    pass
            return

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            loop.run_until_complete(self.async_scan(normalized_url))
        except KeyboardInterrupt:
            self.print_status("Scan interrupted by user", "warning")
        except Exception as e:
            self.print_status(f"Scan error: {str(e)}", "error")
            if self.verbose:
                import traceback
                traceback.print_exc()
        finally:
            try:
                if self.aiohttp_session:
                    loop.run_until_complete(self.aiohttp_session.close())
                loop.close()
            except:
                pass
    except Exception as e:
        self.print_status(f"Initialization error: {str(e)}", "error")
        if self.verbose:
            import traceback
            traceback.print_exc()
